package backup

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"api/internal/router"
)

// Deps are the host hooks the backup service needs, injected from main so this
// package never imports the subsystems it reconciles (no import cycle).
type Deps struct {
	DB           func() *sql.DB // raw handle (database.Get)
	PanelVersion string
	// Reconcile re-applies live state after an import (nftables, WireGuard, ACLs,
	// fleet listener). Returns the subsystems it touched, for the response.
	Reconcile func() []string
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
		Passphrase string `json:"passphrase"`
		Users      bool   `json:"users"`
		Fleet      bool   `json:"fleet"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Passphrase) < MinPassphrase {
		router.JSONError(w, fmt.Sprintf("passphrase must be at least %d characters", MinPassphrase), http.StatusBadRequest)
		return
	}
	db := s.db()
	if db == nil {
		router.JSONError(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	data, err := Export(db, req.Passphrase, s.deps.PanelVersion, req.Users, req.Fleet)
	if err != nil {
		router.JSONError(w, "export failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	name := "wire-panel-" + time.Now().Format("20060102-150405") + ".wgbackup"
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
	hdr, doc, err := Open([]byte(req.Backup), req.Passphrase)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	db := s.db()
	if db == nil {
		router.JSONError(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	if err := Import(db, doc); err != nil {
		router.JSONError(w, "import failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	var reconciled []string
	if s.deps.Reconcile != nil {
		reconciled = s.deps.Reconcile()
	}
	router.JSON(w, map[string]any{
		"ok":         true,
		"includes":   hdr.Includes,
		"reconciled": reconciled,
	})
}

type fileReq struct {
	Passphrase string `json:"passphrase"`
	Backup     string `json:"backup"`
	Confirm    bool   `json:"confirm"`
}

func (s *Service) decodeFile(w http.ResponseWriter, r *http.Request) (fileReq, bool) {
	// Body size is already capped by the router's global bodySizeLimit middleware,
	// which runs ahead of every handler — no local MaxBytesReader needed here.
	var req fileReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
