package fleet

import (
	"compress/gzip"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"api/internal/router"
)

// CVE is one stored Trivy finding for a machine.
type CVE struct {
	CVEID     string `json:"cve_id"`
	Pkg       string `json:"pkg"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed"`
	Severity  string `json:"severity"`
	Target    string `json:"target"`  // the exact manifest/lockfile path (or OS name)
	Project   string `json:"project"` // OS, or the manifest's directory (≈ the project)
	Class     string `json:"class"`   // os-pkgs | lang-pkgs
	Type      string `json:"type"`
	Title     string `json:"title"`
}

// CVEGroup is one bucket of a machine's findings: the OS, or an app project (the
// directory holding its manifests). Sorted worst-first, it drives the grouping.
type CVEGroup struct {
	Project  string `json:"project"`
	Class    string `json:"class"`
	Type     string `json:"type"`
	Total    int    `json:"total"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Fixable  int    `json:"fixable"` // has a fixed version
}

// CVESummary is the machine-level roll-up. Total is raw findings (CVE×package) — noisy on a
// full-OS scan — so the UI leads with UniqueCVEs, Packages, the severity split, and Fixable
// (the actionable number: findings with a fix available).
type CVESummary struct {
	Total      int `json:"total"`       // raw findings (CVE × package rows)
	UniqueCVEs int `json:"unique_cves"` // distinct CVE ids
	Packages   int `json:"packages"`    // distinct affected packages
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Fixable    int `json:"fixable"` // findings with a fixed version available
}

// deriveProject buckets a finding: kernel packages → "Kernel" (fixed by a new kernel +
// reboot, NOT a per-package upgrade); other OS packages → "OS"; an app dependency → the
// DIRECTORY of its manifest (so go.mod + go.sum group together), not the raw file path.
func deriveProject(class, target, pkg string) string {
	if class == "os-pkgs" || class == "" {
		if isKernelPkg(pkg) {
			return "Kernel"
		}
		return "OS"
	}
	if i := strings.LastIndexByte(target, '/'); i > 0 {
		return target[:i]
	}
	return target
}

// isKernelPkg matches the version-pinned kernel-family packages (linux-image-6.8.0-90,
// linux-headers-…, linux-tools-…, …). Trivy names the installed kernel package but the
// fix is a different kernel version, so `apt --only-upgrade` can't touch these.
func isKernelPkg(pkg string) bool {
	for _, p := range []string{"linux-image", "linux-headers", "linux-modules", "linux-tools", "linux-cloud-tools", "linux-buildinfo", "linux-generic"} {
		if strings.HasPrefix(pkg, p) {
			return true
		}
	}
	return false
}

// IngestCVEs replaces a machine's stored findings with the latest full scan (a snapshot,
// not history — the newest scan is the truth), in one transaction.
func (s *Service) IngestCVEs(machineID, scannedAt string, findings []CVE) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM fleet_cves WHERE machine_id = ?`, machineID); err != nil {
		_ = tx.Rollback()
		return err
	}
	// Batched multi-row INSERT (up to batchRows per statement) instead of one Exec per
	// finding — a large scan can be tens of thousands of rows, and per-row round-trips
	// dominate the ingest. 12 columns × 1000 rows = 12000 bind params, well under SQLite's
	// variable limit.
	const batchRows = 1000
	const valueTuple = "(?,?,?,?,?,?,?,?,?,?,?,?)"
	const prefix = `INSERT INTO fleet_cves
		(machine_id, cve_id, pkg, installed, fixed, severity, target, project, class, type, title, scanned_at)
		VALUES `

	args := make([]any, 0, batchRows*12)
	rows := 0
	flush := func() error {
		if rows == 0 {
			return nil
		}
		q := prefix + valueTuple + strings.Repeat(","+valueTuple, rows-1)
		_, err := tx.Exec(q, args...)
		args = args[:0]
		rows = 0
		return err
	}
	for _, f := range findings {
		project := f.Project
		if project == "" {
			project = deriveProject(f.Class, f.Target, f.Pkg)
		}
		args = append(args, machineID, f.CVEID, f.Pkg, f.Installed, f.Fixed, f.Severity,
			f.Target, project, f.Class, f.Type, f.Title, scannedAt)
		rows++
		if rows >= batchRows {
			if err := flush(); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	if err := flush(); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// HandleCVEReport (POST, mTLS) ingests a machine's full CVE list (gzip-compressed). The
// machine comes from the client cert.
func (s *Service) HandleCVEReport(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	var body io.Reader = http.MaxBytesReader(w, r.Body, 64<<20) // 64 MiB compressed cap
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad gzip")
			return
		}
		defer gz.Close()
		body = gz
	}
	var payload struct {
		ScannedAt string `json:"scanned_at"`
		Findings  []struct {
			ID        string `json:"id"`
			Pkg       string `json:"pkg"`
			Installed string `json:"installed"`
			Fixed     string `json:"fixed"`
			Severity  string `json:"severity"`
			Target    string `json:"target"`
			Class     string `json:"class"`
			Type      string `json:"type"`
			Title     string `json:"title"`
		} `json:"findings"`
	}
	// Cap the decompressed stream too (decompression-bomb guard).
	if err := json.NewDecoder(io.LimitReader(body, 512<<20)).Decode(&payload); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	const maxFindings = 200000
	if len(payload.Findings) > maxFindings {
		payload.Findings = payload.Findings[:maxFindings]
	}
	cves := make([]CVE, len(payload.Findings))
	for i, f := range payload.Findings {
		cves[i] = CVE{CVEID: f.ID, Pkg: f.Pkg, Installed: f.Installed, Fixed: f.Fixed,
			Severity: f.Severity, Target: f.Target, Project: deriveProject(f.Class, f.Target, f.Pkg),
			Class: f.Class, Type: f.Type, Title: f.Title}
	}
	if err := s.IngestCVEs(m.ID, payload.ScannedAt, cves); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"stored": len(cves)})
}

// CVEGroups returns a machine's findings bucketed by project, worst-first.
func (s *Service) CVEGroups(machineID string) ([]CVEGroup, error) {
	rows, err := s.db.Query(`SELECT project, MAX(class), MAX(type),
		COUNT(*),
		SUM(severity='CRITICAL'), SUM(severity='HIGH'), SUM(severity='MEDIUM'), SUM(severity='LOW'),
		SUM(fixed != '' AND fixed IS NOT NULL)
		FROM fleet_cves WHERE machine_id = ?
		GROUP BY project
		ORDER BY SUM(severity='CRITICAL') DESC, SUM(severity='HIGH') DESC, COUNT(*) DESC`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CVEGroup{}
	for rows.Next() {
		var g CVEGroup
		if err := rows.Scan(&g.Project, &g.Class, &g.Type, &g.Total, &g.Critical, &g.High, &g.Medium, &g.Low, &g.Fixable); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CVESummaryFor returns the machine-level roll-up in one query.
func (s *Service) CVESummaryFor(machineID string) (CVESummary, error) {
	var sm CVESummary
	err := s.db.QueryRow(`SELECT
		COUNT(*),
		COUNT(DISTINCT cve_id),
		COUNT(DISTINCT pkg),
		COALESCE(SUM(severity='CRITICAL'),0), COALESCE(SUM(severity='HIGH'),0),
		COALESCE(SUM(severity='MEDIUM'),0), COALESCE(SUM(severity='LOW'),0),
		COALESCE(SUM(fixed != '' AND fixed IS NOT NULL),0)
		FROM fleet_cves WHERE machine_id = ?`, machineID).
		Scan(&sm.Total, &sm.UniqueCVEs, &sm.Packages, &sm.Critical, &sm.High, &sm.Medium, &sm.Low, &sm.Fixable)
	return sm, err
}

// ListCVEs returns a filtered, paginated page of a machine's findings plus the total
// matching count. Filters (all optional): severity, class, target, fixable(=only rows
// with a fix), q (substring on cve id or package).
func (s *Service) ListCVEs(machineID string, f cveFilter) ([]CVE, int, error) {
	where := []string{"machine_id = ?"}
	args := []any{machineID}
	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, strings.ToUpper(f.Severity))
	}
	if f.Class != "" {
		where = append(where, "class = ?")
		args = append(args, f.Class)
	}
	if f.Project != "" {
		where = append(where, "project = ?")
		args = append(args, f.Project)
	}
	if f.Fixable {
		where = append(where, "fixed != '' AND fixed IS NOT NULL")
	}
	if f.Q != "" {
		where = append(where, "(cve_id LIKE ? OR pkg LIKE ?)")
		args = append(args, "%"+f.Q+"%", "%"+f.Q+"%")
	}
	if f.CVEID != "" {
		where = append(where, "cve_id = ?")
		args = append(args, f.CVEID)
	}
	cond := strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM fleet_cves WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	// worst-first, fixable before no-fix, then by CVE id.
	q := `SELECT cve_id, pkg, installed, fixed, severity, target, project, class, type, title
		FROM fleet_cves WHERE ` + cond + `
		ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,
		         (fixed != '' AND fixed IS NOT NULL) DESC, cve_id
		LIMIT ? OFFSET ?`
	args = append(args, f.limit(), f.offset())
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []CVE{}
	for rows.Next() {
		var c CVE
		if err := rows.Scan(&c.CVEID, &c.Pkg, &c.Installed, &c.Fixed, &c.Severity, &c.Target, &c.Project, &c.Class, &c.Type, &c.Title); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

type cveFilter struct {
	Severity, Class, Project, Q, CVEID string
	Fixable                            bool
	Limit, Offset                      int
}

// CVERow is one unique CVE across a machine's findings (for the CVE-first list).
type CVERow struct {
	CVEID    string `json:"cve_id"`
	Severity string `json:"severity"`
	Packages int    `json:"packages"` // distinct affected packages
	Fixable  bool   `json:"fixable"`  // at least one affected package has a fix
	Title    string `json:"title,omitempty"`
}

var sevByRank = map[int]string{4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "UNKNOWN"}
var rankBySev = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

const sevRankExpr = `CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END`

// ListCVEsByCVE returns unique CVEs (one row per cve_id) for a machine, worst-first
// then fixable-first, paginated. severity/fixable filter the GROUPED result (a CVE's
// worst severity / whether any affected package has a fix); q matches the id or any
// package. Pairs with ListCVEs(cveFilter{CVEID: ...}) for the per-CVE drill-down.
func (s *Service) ListCVEsByCVE(machineID string, f cveFilter) ([]CVERow, int, error) {
	where := []string{"machine_id = ?"}
	args := []any{machineID}
	if f.Q != "" {
		where = append(where, "(cve_id LIKE ? OR pkg LIKE ?)")
		args = append(args, "%"+f.Q+"%", "%"+f.Q+"%")
	}
	var having []string
	if r, ok := rankBySev[strings.ToUpper(f.Severity)]; ok {
		having = append(having, "MAX("+sevRankExpr+") = "+strconv.Itoa(r))
	}
	if f.Fixable {
		having = append(having, "MAX(fixed != '' AND fixed IS NOT NULL) = 1")
	}
	cond := strings.Join(where, " AND ")
	havingClause := ""
	if len(having) > 0 {
		havingClause = " HAVING " + strings.Join(having, " AND ")
	}

	var total int
	countQ := `SELECT COUNT(*) FROM (SELECT cve_id FROM fleet_cves WHERE ` + cond + ` GROUP BY cve_id` + havingClause + `)`
	if err := s.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := `SELECT cve_id, MAX(` + sevRankExpr + `) AS sev,
		COUNT(DISTINCT pkg) AS packages,
		MAX(fixed != '' AND fixed IS NOT NULL) AS fixable,
		MAX(title) AS title
		FROM fleet_cves WHERE ` + cond + `
		GROUP BY cve_id` + havingClause + `
		ORDER BY sev DESC, fixable DESC, cve_id
		LIMIT ? OFFSET ?`
	args = append(args, f.limit(), f.offset())
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []CVERow{}
	for rows.Next() {
		var c CVERow
		var sev, fixable int
		var title sql.NullString
		if err := rows.Scan(&c.CVEID, &sev, &c.Packages, &fixable, &title); err != nil {
			return nil, 0, err
		}
		c.Severity, c.Fixable, c.Title = sevByRank[sev], fixable == 1, title.String
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func (f cveFilter) limit() int {
	if f.Limit <= 0 || f.Limit > 500 {
		return 200
	}
	return f.Limit
}
func (f cveFilter) offset() int {
	if f.Offset < 0 {
		return 0
	}
	return f.Offset
}

// --- admin handlers (normal authenticated router) ---

// handleCVEGroups (GET /api/fleet/cves/groups?machine_id=) returns the grouped summary.
func (s *Service) handleCVEGroups(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("machine_id")
	if id == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	groups, err := s.CVEGroups(id)
	if err != nil {
		router.JSONError(w, "query failed", http.StatusInternalServerError)
		return
	}
	summary, err := s.CVESummaryFor(id)
	if err != nil {
		router.JSONError(w, "query failed", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{"summary": summary, "groups": groups})
}

// handleListCVEs (GET /api/fleet/cves?machine_id=&severity=&class=&target=&fixable=&q=&limit=&offset=).
func (s *Service) handleListCVEs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("machine_id")
	if id == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	cves, total, err := s.ListCVEs(id, cveFilter{
		Severity: q.Get("severity"), Class: q.Get("class"), Project: q.Get("project"),
		Q: q.Get("q"), CVEID: q.Get("cve_id"), Fixable: q.Get("fixable") == "1" || q.Get("fixable") == "true",
		Limit: limit, Offset: offset,
	})
	if err != nil {
		router.JSONError(w, "query failed", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{"cves": cves, "total": total})
}

// handleListCVEsByCVE (GET /api/fleet/cves/by-cve?machine_id=&severity=&fixable=&q=&limit=&offset=)
// returns unique CVEs (one row per cve_id) for the CVE-first list.
func (s *Service) handleListCVEsByCVE(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("machine_id")
	if id == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	cves, total, err := s.ListCVEsByCVE(id, cveFilter{
		Severity: q.Get("severity"),
		Q:        q.Get("q"), Fixable: q.Get("fixable") == "1" || q.Get("fixable") == "true",
		Limit: limit, Offset: offset,
	})
	if err != nil {
		router.JSONError(w, "query failed", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{"cves": cves, "total": total})
}

// handleExportCVEs (GET /api/fleet/cves/export?machine_id=&<filters>) streams the
// filtered findings as a CSV attachment — for offline triage or feeding an external
// fixer. Same filters as the list; no pagination (whole matching set, capped).
func (s *Service) handleExportCVEs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("machine_id")
	if id == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	cves, _, err := s.ListCVEs(id, cveFilter{
		Severity: q.Get("severity"), Class: q.Get("class"), Project: q.Get("project"),
		Q: q.Get("q"), Fixable: q.Get("fixable") == "1" || q.Get("fixable") == "true",
		Limit: 50000, // export cap
	})
	if err != nil {
		router.JSONError(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="cves.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"cve_id", "severity", "package", "installed", "fixed", "project", "target", "class", "type", "title"})
	for _, c := range cves {
		_ = cw.Write([]string{csvSafe(c.CVEID), csvSafe(c.Severity), csvSafe(c.Pkg), csvSafe(c.Installed),
			csvSafe(c.Fixed), csvSafe(c.Project), csvSafe(c.Target), csvSafe(c.Class), csvSafe(c.Type), csvSafe(c.Title)})
	}
	cw.Flush()
}

// csvSafe neutralizes CSV formula injection. A cell that opens with =, +, -, @, or a
// control char is interpreted as a formula by Excel/Sheets; a Trivy title is
// attacker-influenced (it comes from the advisory text), so prefix such cells with a
// tab so the spreadsheet treats them as literal text.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "\t" + s
	}
	return s
}

// handleFixPackages (POST /api/fleet/fix {machine_id, packages}) queues a targeted
// OS-package upgrade for the selected CVEs.
func (s *Service) handleFixPackages(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineID string   `json:"machine_id"`
		Packages  []string `json:"packages"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.MachineID == "" {
		router.JSONError(w, "machine_id + packages required", http.StatusBadRequest)
		return
	}
	if len(req.Packages) == 0 {
		router.JSONError(w, "no packages selected", http.StatusBadRequest)
		return
	}
	payload, _ := json.Marshal(map[string]any{"packages": req.Packages})
	cid, err := s.Enqueue(req.MachineID, "fix-packages", payload)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	router.JSON(w, map[string]any{"command_id": cid, "count": len(req.Packages)})
}
