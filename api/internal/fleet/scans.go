package fleet

import (
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"api/internal/router"
)

// Scan history: one summary row per vulnerability scan (fleet_scans), kept beside the latest
// scan's full findings (fleet_cves). Rows hold counts and what changed since the previous
// scan, never the findings themselves. Retention per machine: the newest scanHistoryMax
// rows, none older than scanHistoryAge.
const (
	scanHistoryMax = 100
	scanHistoryAge = 180 * 24 * time.Hour
	scanChangedMax = 500 // CVE ids kept per direction (new / fixed) for the "what changed" view
	scanErrorMax   = 300 // runes of a failure reason
)

// scanMeta is a scan report's metadata, as the agent sends it (validated by normalize).
type scanMeta struct {
	ScannedAt   string `json:"scanned_at"`
	Trigger     string `json:"trigger"`
	Error       string `json:"error"` // a failed scan's reason (/scan-failure)
	Failed      bool   `json:"-"`
	HasFindings bool   `json:"-"` // the report carried its findings list (even an empty one)
	Cost        struct {
		Seconds float64 `json:"seconds"`
		PeakMem int64   `json:"peak_mem"`
	} `json:"cost"`
}

var errBadScanTime = errors.New("bad scanned_at")

// normalize validates what the agent claims before it's stored and shown: the timestamp is
// the row key (re-rendered in canonical UTC so rows sort as text), the trigger is one of ours,
// the reason is one printable line, and the cost numbers stay in range.
func (m *scanMeta) normalize() error {
	t, err := time.Parse(time.RFC3339, m.ScannedAt)
	if err != nil || t.After(time.Now().Add(5*time.Minute)) { // clock skew, not the future
		return errBadScanTime
	}
	m.ScannedAt = t.UTC().Format(time.RFC3339)
	if m.Trigger != "kernel" {
		m.Trigger = "manual"
	}
	m.Error = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(m.Error))
	if utf8.RuneCountInString(m.Error) > scanErrorMax {
		m.Error = string([]rune(m.Error)[:scanErrorMax]) + "…"
	}
	if m.Failed && m.Error == "" {
		m.Error = "scan failed"
	}
	m.Cost.Seconds = min(max(m.Cost.Seconds, 0), 7*24*3600)
	m.Cost.PeakMem = min(max(m.Cost.PeakMem, 0), 1<<44)
	return nil
}

// scanSummary is one scan's counts. Severities count distinct CVEs (each at its worst
// severity on the machine); Findings counts CVE×package rows; New/Fixed are nil on a
// machine's first scan (nothing to compare with).
type scanSummary struct {
	Findings, CVEs                       int
	Critical, High, Medium, Low, Unknown int
	Fixable                              int
	New, Fixed                           *int
	NewIDs, FixedIDs                     []string
}

var sevRank = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

// summarizeScan counts findings and diffs their CVE ids against the previous scan's (prev is
// nil when there was none).
func summarizeScan(findings []CVE, prev map[string]bool) scanSummary {
	sum := scanSummary{Findings: len(findings)}
	worst := map[string]int{}
	for _, f := range findings {
		if f.Fixed != "" {
			sum.Fixable++
		}
		if r, ok := worst[f.CVEID]; !ok || sevRank[strings.ToUpper(f.Severity)] > r {
			worst[f.CVEID] = sevRank[strings.ToUpper(f.Severity)]
		}
	}
	sum.CVEs = len(worst)
	for _, r := range worst {
		switch r {
		case 4:
			sum.Critical++
		case 3:
			sum.High++
		case 2:
			sum.Medium++
		case 1:
			sum.Low++
		default:
			sum.Unknown++
		}
	}
	if prev == nil {
		return sum
	}
	for id := range worst {
		if !prev[id] {
			sum.NewIDs = append(sum.NewIDs, id)
		}
	}
	for id := range prev {
		if _, ok := worst[id]; !ok {
			sum.FixedIDs = append(sum.FixedIDs, id)
		}
	}
	nNew, nFixed := len(sum.NewIDs), len(sum.FixedIDs)
	sum.New, sum.Fixed = &nNew, &nFixed
	sum.NewIDs, sum.FixedIDs = capIDs(sum.NewIDs), capIDs(sum.FixedIDs)
	return sum
}

func capIDs(ids []string) []string {
	sort.Strings(ids)
	if len(ids) > scanChangedMax {
		ids = ids[:scanChangedMax]
	}
	return ids
}

// scanStored reports whether this scan (machine + timestamp) is already in the history.
func scanStored(tx *sql.Tx, machineID, scannedAt string) (bool, error) {
	var n int
	err := tx.QueryRow(`SELECT COUNT(*) FROM fleet_scans WHERE machine_id = ? AND scanned_at = ?`, machineID, scannedAt).Scan(&n)
	return n > 0, err
}

// storedCVEIDs returns the distinct CVE ids of the machine's current findings, or nil when it
// has never been scanned (so the first scan shows no "new" flood).
func storedCVEIDs(tx *sql.Tx, machineID string) (map[string]bool, error) {
	var scans int
	if err := tx.QueryRow(`SELECT (SELECT COUNT(*) FROM fleet_scans WHERE machine_id = ? AND status = 'ok')
		+ (SELECT COUNT(*) FROM fleet_cves WHERE machine_id = ?)`, machineID, machineID).Scan(&scans); err != nil || scans == 0 {
		return nil, err
	}
	rows, err := tx.Query(`SELECT DISTINCT cve_id FROM fleet_cves WHERE machine_id = ?`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids[id] = true
	}
	return ids, rows.Err()
}

// recordScan adds a finished scan's summary to the history and applies retention.
func recordScan(tx *sql.Tx, machineID string, meta scanMeta, sum scanSummary) error {
	newIDs, _ := json.Marshal(sum.NewIDs)
	fixedIDs, _ := json.Marshal(sum.FixedIDs)
	if _, err := tx.Exec(`INSERT INTO fleet_scans (machine_id, scanned_at, trigger, status, seconds, peak_mem,
		findings, cves, critical, high, medium, low, unknown, fixable, new_count, fixed_count, new_ids, fixed_ids)
		VALUES (?, ?, ?, 'ok', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		machineID, meta.ScannedAt, meta.Trigger, meta.Cost.Seconds, meta.Cost.PeakMem,
		sum.Findings, sum.CVEs, sum.Critical, sum.High, sum.Medium, sum.Low, sum.Unknown, sum.Fixable,
		sum.New, sum.Fixed, string(newIDs), string(fixedIDs)); err != nil {
		return err
	}
	return pruneScans(tx, machineID)
}

// HandleScanFailure (POST /scan-failure, mTLS) records a scan that didn't finish, as history
// only: the machine's findings stay those of its last finished scan. /cve-report, by contrast,
// always carries the findings, so a report without them is refused rather than read as clean.
func (s *Service) HandleScanFailure(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	if m == nil {
		writeErr(w, http.StatusUnauthorized, "unknown machine")
		return
	}
	body, ok := reportBody(w, r, 1<<14)
	if !ok {
		return
	}
	defer body.Close()
	var meta scanMeta
	err := json.NewDecoder(body).Decode(&meta)
	meta.Failed = true
	if err == nil {
		err = meta.normalize()
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := s.RecordScanFailure(m.ID, meta); err != nil {
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"stored": 1})
}

// reportBody returns an agent report's body, gunzipped when sent compressed, capped at limit
// bytes both on the wire and decompressed (a gzip bomb stops at the cap). It writes the 400
// itself when the body can't be read.
func reportBody(w http.ResponseWriter, r *http.Request, limit int64) (io.ReadCloser, bool) {
	body := http.MaxBytesReader(w, r.Body, limit)
	if r.Header.Get("Content-Encoding") != "gzip" {
		return body, true
	}
	gz, err := gzip.NewReader(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad gzip")
		return nil, false
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(gz, limit), gz}, true
}

// RecordScanFailure adds a scan that didn't finish to the history (a repeat is ignored).
func (s *Service) RecordScanFailure(machineID string, meta scanMeta) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO fleet_scans (machine_id, scanned_at, trigger, status, error, seconds)
		VALUES (?, ?, ?, 'failed', ?, ?)`, machineID, meta.ScannedAt, meta.Trigger, meta.Error, meta.Cost.Seconds); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := pruneScans(tx, machineID); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// pruneScans keeps a machine's newest scanHistoryMax rows, none older than scanHistoryAge.
func pruneScans(tx *sql.Tx, machineID string) error {
	cutoff := time.Now().Add(-scanHistoryAge).UTC().Format(time.RFC3339)
	_, err := tx.Exec(`DELETE FROM fleet_scans WHERE machine_id = ? AND (scanned_at < ? OR scanned_at NOT IN
		(SELECT scanned_at FROM fleet_scans WHERE machine_id = ? ORDER BY scanned_at DESC LIMIT ?))`,
		machineID, cutoff, machineID, scanHistoryMax)
	return err
}

// ScanRow is one history entry as the UI shows it (the changed ids come from ScanChanges).
type ScanRow struct {
	ScannedAt string  `json:"scanned_at"`
	Trigger   string  `json:"trigger"`
	Status    string  `json:"status"` // ok | failed
	Error     string  `json:"error,omitempty"`
	Seconds   float64 `json:"seconds"`
	PeakMem   int64   `json:"peak_mem"`
	Findings  int     `json:"findings"`
	CVEs      int     `json:"cves"`
	Critical  int     `json:"critical"`
	High      int     `json:"high"`
	Medium    int     `json:"medium"`
	Low       int     `json:"low"`
	Unknown   int     `json:"unknown"`
	Fixable   int     `json:"fixable"`
	New       *int    `json:"new"`   // nil on a first scan
	Fixed     *int    `json:"fixed"` // nil on a first scan
}

// ScanHistory returns a machine's scans, newest first.
func (s *Service) ScanHistory(machineID string) ([]ScanRow, error) {
	rows, err := s.db.Query(`SELECT scanned_at, trigger, status, COALESCE(error, ''), COALESCE(seconds, 0),
		COALESCE(peak_mem, 0), COALESCE(findings, 0), COALESCE(cves, 0), COALESCE(critical, 0), COALESCE(high, 0),
		COALESCE(medium, 0), COALESCE(low, 0), COALESCE(unknown, 0), COALESCE(fixable, 0), new_count, fixed_count
		FROM fleet_scans WHERE machine_id = ? ORDER BY scanned_at DESC LIMIT ?`, machineID, scanHistoryMax)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScanRow{}
	for rows.Next() {
		var r ScanRow
		var n, f sql.NullInt64
		if err := rows.Scan(&r.ScannedAt, &r.Trigger, &r.Status, &r.Error, &r.Seconds, &r.PeakMem, &r.Findings,
			&r.CVEs, &r.Critical, &r.High, &r.Medium, &r.Low, &r.Unknown, &r.Fixable, &n, &f); err != nil {
			return nil, err
		}
		if n.Valid && f.Valid {
			nv, fv := int(n.Int64), int(f.Int64)
			r.New, r.Fixed = &nv, &fv
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ScanChanges returns the CVE ids a scan found new and fixed (each capped at scanChangedMax).
func (s *Service) ScanChanges(machineID, scannedAt string) (newIDs, fixedIDs []string, err error) {
	var n, f sql.NullString
	err = s.db.QueryRow(`SELECT new_ids, fixed_ids FROM fleet_scans WHERE machine_id = ? AND scanned_at = ?`,
		machineID, scannedAt).Scan(&n, &f)
	if err != nil {
		return nil, nil, err
	}
	newIDs, fixedIDs = []string{}, []string{}
	_ = json.Unmarshal([]byte(n.String), &newIDs)
	_ = json.Unmarshal([]byte(f.String), &fixedIDs)
	return newIDs, fixedIDs, nil
}

// handleScanHistory (GET /api/fleet/scans?machine_id=) lists a machine's scan history.
func (s *Service) handleScanHistory(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("machine_id")
	if id == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	if !s.requireMachineAccess(w, r, id) {
		return
	}
	scans, err := s.ScanHistory(id)
	if err != nil {
		router.JSONError(w, "query failed", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{"scans": scans})
}

// handleScanChanges (GET /api/fleet/scans/changes?machine_id=&scanned_at=) returns what one scan
// found new and fixed.
func (s *Service) handleScanChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id, at := q.Get("machine_id"), q.Get("scanned_at")
	if id == "" || at == "" {
		router.JSONError(w, "machine_id and scanned_at required", http.StatusBadRequest)
		return
	}
	if !s.requireMachineAccess(w, r, id) {
		return
	}
	newIDs, fixedIDs, err := s.ScanChanges(id, at)
	if errors.Is(err, sql.ErrNoRows) {
		router.JSONError(w, "scan not found", http.StatusNotFound)
		return
	}
	if err != nil {
		router.JSONError(w, "query failed", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{"new": newIDs, "fixed": fixedIDs})
}
