package backup

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"api/internal/auth"
	"api/internal/router"
)

// requireStepUp re-authenticates the caller (password + fresh TOTP when enabled) before a sensitive
// backup action. The backup path is a second write-door into the identity store (export decrypts
// every secret; import replaces the users table), so export+import demand step-up on top of their
// owner-only gate. Returns the principal and true on success; else writes a 428 and returns false.
func requireStepUp(w http.ResponseWriter, r *http.Request, currentPassword, totpCode string) (*router.Principal, bool) {
	p := router.CurrentUser(r)
	if p == nil {
		router.JSONError(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	a := auth.GetService()
	if a == nil {
		router.JSONError(w, "auth unavailable", http.StatusServiceUnavailable)
		return nil, false
	}
	if !a.StepUp(w, p.UserID, currentPassword, totpCode) {
		return nil, false
	}
	return p, true
}

// Deps are the host hooks the backup service needs, injected from main so this
// package never imports the subsystems it reconciles (no import cycle).
type Deps struct {
	DB           func() *sql.DB // raw handle (database.Get)
	PanelVersion string
	// Reconcile re-applies live state after an import (nftables, WireGuard, ACLs,
	// fleet listener). Returns the subsystems it touched, for the response.
	Reconcile func() []string
	// WireGuardKey returns the WireGuard server's private key for an export, and
	// RestoreWireGuardKey installs one from an import. Nil when WireGuard is disabled here.
	WireGuardKey        func() string
	RestoreWireGuardKey func(privateKey string) error
}

type Service struct{ deps Deps }

func New(d Deps) *Service { return &Service{deps: d} }

// Handlers registers the admin-router endpoints (session-gated, like the rest of
// the panel API). Export/Preview/Import all POST.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"Export":  s.handleExport,
		"Preview": s.handlePreview,
		"Import":  s.handleImport,
		// Off-host (scheduled, automated upload of the sealed bundle to S3/SFTP).
		"OffhostGetConfig":  s.handleOffhostGetConfig,
		"OffhostSaveConfig": s.handleOffhostSaveConfig,
		"OffhostTest":       s.handleOffhostTest,
		"OffhostRun":        s.handleOffhostRunNow,
		"OffhostList":       s.handleOffhostList,
		"OffhostStatus":     s.handleOffhostStatus,
		"OffhostRestore":    s.handleOffhostRestore,
	}
}

func (s *Service) db() *sql.DB {
	if s.deps.DB == nil {
		return nil
	}
	return s.deps.DB()
}

// handleExport builds a passphrase-sealed backup and streams it as a download.
// POST /api/backup/export  { passphrase, users, fleet }
func (s *Service) handleExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Passphrase      string `json:"passphrase"`
		Users           bool   `json:"users"`
		Fleet           bool   `json:"fleet"`
		CurrentPassword string `json:"currentPassword"`
		TotpCode        string `json:"totpCode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, ok := requireStepUp(w, r, req.CurrentPassword, req.TotpCode); !ok {
		return
	}
	if err := ValidatePassphrase(req.Passphrase); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	db := s.db()
	if db == nil {
		router.JSONError(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	data, err := Export(db, req.Passphrase, s.deps.PanelVersion, req.Users, req.Fleet, s.wireguardKey())
	if err != nil {
		router.JSONError(w, "export failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	name := "motte-" + time.Now().Format("20060102-150405") + ".wgbackup"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// handlePreview decrypts a backup and reports what an import would do — no writes.
// POST /api/backup/preview  { passphrase, backup }
func (s *Service) handlePreview(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodeFile(w, r)
	if !ok {
		return
	}
	hdr, doc, err := Open([]byte(req.Backup), req.Passphrase)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	router.JSON(w, map[string]any{
		"header":   hdr,
		"plan":     Plan(s.db(), doc),
		"warnings": warnings(hdr),
	})
}

// handleImport applies a backup (faithful replace) then reconciles live state.
// POST /api/backup/import  { passphrase, backup, confirm }
func (s *Service) handleImport(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decodeFile(w, r)
	if !ok {
		return
	}
	if !req.Confirm {
		router.JSONError(w, "confirmation required", http.StatusBadRequest)
		return
	}
	if _, ok := requireStepUp(w, r, req.CurrentPassword, req.TotpCode); !ok {
		return
	}
	hdr, doc, err := Open([]byte(req.Backup), req.Passphrase)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	reconciled, err := s.apply(doc)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]any{
		"ok":         true,
		"includes":   hdr.Includes,
		"reconciled": reconciled,
	})
}

// wireguardKey is the WireGuard server key to seal into an export ("" when WireGuard is off).
func (s *Service) wireguardKey() string {
	if s.deps.WireGuardKey == nil {
		return ""
	}
	return s.deps.WireGuardKey()
}

// apply imports a backup document (faithful replace), installs its WireGuard server key, then
// re-applies live state. Shared by the upload import and the off-host restore.
func (s *Service) apply(doc *Document) ([]string, error) {
	db := s.db()
	if db == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	if err := Import(db, doc); err != nil {
		return nil, fmt.Errorf("import failed: %w", err)
	}
	if doc.WireGuardKey != "" && s.deps.RestoreWireGuardKey != nil {
		if err := s.deps.RestoreWireGuardKey(doc.WireGuardKey); err != nil {
			return nil, fmt.Errorf("restore WireGuard key: %w", err)
		}
	}
	var reconciled []string
	if s.deps.Reconcile != nil {
		reconciled = s.deps.Reconcile()
	}
	return reconciled, nil
}

type fileReq struct {
	Passphrase      string `json:"passphrase"`
	Backup          string `json:"backup"`
	Confirm         bool   `json:"confirm"`
	CurrentPassword string `json:"currentPassword"`
	TotpCode        string `json:"totpCode"`
}

func (s *Service) decodeFile(w http.ResponseWriter, r *http.Request) (fileReq, bool) {
	// Body size is already capped by the router's global bodySizeLimit middleware,
	// which runs ahead of every handler — no local MaxBytesReader needed here.
	var req fileReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if tooLarge := new(http.MaxBytesError); errors.As(err, &tooLarge) {
			router.JSONError(w, fmt.Sprintf("backup file is too large (limit %d MB)", tooLarge.Limit>>20), http.StatusRequestEntityTooLarge)
			return req, false
		}
		router.JSONError(w, "bad request", http.StatusBadRequest)
		return req, false
	}
	if req.Backup == "" {
		router.JSONError(w, "no backup file provided", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

// warnings surfaces the human consequences of the opt-in tiers before import.
func warnings(h Header) []string {
	var out []string
	for _, inc := range h.Includes {
		switch inc {
		case "users":
			out = append(out, "Admin users will be replaced — ALL admins are signed out on every device, and you must log in with the imported credentials.")
		case "fleet":
			out = append(out, "The fleet CA and machines will be replaced. Existing agents keep working only if they can still reach this host at the configured panel address.")
		}
	}
	return out
}
