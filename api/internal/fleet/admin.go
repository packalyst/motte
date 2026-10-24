package fleet

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// Admin handlers run on the panel's NORMAL authenticated API router (not the
// fleet mTLS listener). They let the operator mint enrollment tokens and view the
// fleet. Registered as the "fleet" service in endpoints.json.
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"CreateToken":            s.handleCreateToken,
		"ListTokens":             s.handleListTokens,
		"DeleteToken":            s.handleDeleteToken,
		"ListMachines":           s.handleListMachines,
		"CAInfo":                 s.handleCAInfo,
		"EnqueueCommand":         s.handleEnqueueCommand,
		"BulkCommand":            s.handleBulkCommand,
		"MachineReport":          s.handleMachineReport,
		"MetricsHistory":         s.handleMetricsHistory,
		"FleetEndpoints":         s.handleEndpoints,
		"SetConfig":              s.handleSetConfig,
		"PushBlocks":             s.handlePushBlocks,
		"ClearBlocks":            s.handleClearBlocks,
		"DeleteMachine":          s.handleDeleteMachine,
		"SetMachineTags":         s.handleSetMachineTags,
		"CVEGroups":              s.handleCVEGroups,
		"ListCVEs":               s.handleListCVEs,
		"ListCVEsByCVE":          s.handleListCVEsByCVE,
		"ScanHistory":            s.handleScanHistory,
		"ScanChanges":            s.handleScanChanges,
		"ListDirs":               s.handleListDirs,
		"CheckAgentVersion":      s.handleCheckAgentVersion,
		"ExportCVEs":             s.handleExportCVEs,
		"FixPackages":            s.handleFixPackages,
		"MachineCommands":        s.handleMachineCommands,
		"FIM":                    s.handleFIM,
		"ConsoleGrant":           s.handleConsoleGrant,
		"ConsoleGrantAll":        s.handleConsoleGrantAll,
		"ConsoleToggle":          s.handleConsoleToggle,
		"ConsoleSessions":        s.handleConsoleSessions,
		"ConsoleSnapshot":        s.handleConsoleSnapshot,
		"ConsoleKill":            s.handleConsoleKill,
		"ConsoleForward":         s.handleConsoleForward,
		"ConsoleRecordings":      s.handleConsoleRecordings,
		"ConsoleRecording":       s.handleConsoleRecording,
		"ConsoleRecordingDelete": s.handleConsoleRecordingDelete,
	}
}

// handleDeleteMachine removes a machine and everything tied to it (registry row +
// queued commands), which invalidates its client cert. To return, the host must
// re-enroll with a fresh one-time token.
// POST /api/fleet/machine/delete  {"machine_id":"..."}
func (s *Service) handleDeleteMachine(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineID string `json:"machine_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil || req.MachineID == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	if err := s.DeleteMachine(req.MachineID); err != nil {
		router.JSONError(w, "machine not found", http.StatusNotFound)
		return
	}
	router.JSON(w, map[string]bool{"ok": true})
}

// handleSetMachineTags replaces a machine's tags, which drive tag-based operator scoping.
// Admin+ (scoping is an administrative concern). POST /api/fleet/machine/tags
// {"machine_id":"...","tags":["prod","db"]}
func (s *Service) handleSetMachineTags(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineID string   `json:"machine_id"`
		Tags      []string `json:"tags"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil || req.MachineID == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	if err := s.SetMachineTags(req.MachineID, req.Tags); err != nil {
		var ve *helper.ValidationError
		if errors.As(err, &ve) {
			router.JSONError(w, ve.Message, http.StatusBadRequest)
		} else {
			router.JSONError(w, "machine not found", http.StatusNotFound)
		}
		return
	}
	actor, _ := s.actingAdmin(r)
	events.Audit("fleet", "machine_tags", events.SeverityInfo, actor, helper.GetClientIP(r),
		fmt.Sprintf("Machine %s tags set to [%s]", req.MachineID, strings.Join(req.Tags, ", ")))
	router.JSON(w, map[string]bool{"ok": true})
}

// handlePushBlocks queues a sync-blocks command carrying the panel's current explicit
// blocklist (operator + escalation ip/range entries) so the machine blocks them too.
// POST /api/fleet/push-blocks  {"machine_id":"..."}
func (s *Service) handlePushBlocks(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineID string `json:"machine_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil || req.MachineID == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	payload, count, status, err := s.blocklistPayload()
	if err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}
	// sync-blocks is allow-tier (no step-up); route through the guardrail for audit coverage.
	id, status, err := s.enqueueGuarded(r, req.MachineID, "sync-blocks", "", "", payload)
	if err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}
	router.JSON(w, map[string]any{"command_id": id, "count": count})
}

// blocklistPayload builds the sync-blocks payload from the panel's explicit blocklist (its IP
// and range blocks; country/ASN blocks stay on the panel). It is the only source of that
// payload: the agent replaces its panel list with whatever arrives, so a caller-supplied or
// empty-by-accident list would unblock everything there.
func (s *Service) blocklistPayload() (payload json.RawMessage, count, status int, err error) {
	if s.blockedIPs == nil {
		return nil, 0, http.StatusServiceUnavailable, errors.New("blocklist unavailable")
	}
	ips, err := s.blockedIPs()
	if err != nil {
		log.Printf("fleet: reading the panel blocklist: %v", err)
		return nil, 0, http.StatusInternalServerError, errors.New("couldn't read the panel blocklist; nothing was pushed")
	}
	payload, _ = json.Marshal(map[string]any{"ips": ips})
	return payload, len(ips), 0, nil
}

// userCommandPayload is the payload to queue for a command a user sent (the single and bulk
// command endpoints): the request's own, except a blocklist push, which always carries the
// panel's list built here, never one from the request (an empty one would wipe the machine's
// list without the step-up clear-blocks needs).
func (s *Service) userCommandPayload(ctype string, payload json.RawMessage) (json.RawMessage, int, error) {
	if ctype != "sync-blocks" {
		return payload, http.StatusOK, nil
	}
	p, _, status, err := s.blocklistPayload()
	return p, status, err
}

// handleClearBlocks queues a clear-blocks command that empties the machine's panel-pushed
// blocklist set (CrowdSec/manual bans are untouched). POST /api/fleet/clear-blocks {"machine_id"}
func (s *Service) handleClearBlocks(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineID       string `json:"machine_id"`
		CurrentPassword string `json:"currentPassword"` // step-up: clear-blocks is confirm-tier
		TotpCode        string `json:"totpCode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil || req.MachineID == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	id, status, err := s.enqueueGuarded(r, req.MachineID, "clear-blocks", req.CurrentPassword, req.TotpCode, nil)
	if err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}
	router.JSON(w, map[string]any{"command_id": id})
}

// handleSetConfig turns the fleet listener on/off and sets its port, then applies
// it live (starts/stops the mTLS listener + opens/closes the firewall port). This
// is the "flip a switch" control — no env vars.
// POST /api/fleet/config  {"enabled":true,"port":9443}
func (s *Service) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
		Port    int  `json:"port"`
		// FinishMigration closes the old port of a port change now, without waiting for the
		// machines that haven't reconnected on the new one (they then need reinstalling).
		FinishMigration bool `json:"finish_migration"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		router.JSONError(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Port == 0 {
		req.Port = defaultPort
	}
	if req.Port < 1 || req.Port > 65535 {
		router.JSONError(w, "port out of range", http.StatusBadRequest)
		return
	}
	// Serialize config changes: the migrating-check and the migration start must be one
	// atomic step, or two concurrent POSTs could both pass the check and the second would
	// clobber s.oldSrv, leaking the first listener + its firewall port.
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	// A port migration keeps both ports open until the machines have moved; a second port change
	// mid-flight would strand agents between three ports. Only two things go through meanwhile:
	// switching the listener off (it closes both ports and ends the migration) and finishing the
	// migration now (closes the old port).
	active, endsAt := s.migrationState()
	if req.FinishMigration && !active { // already finished: nothing to change
		s.writeConfigState(w)
		return
	}
	if active {
		if req.FinishMigration {
			actor, _ := s.actingAdmin(r)
			s.finishMigration(actor, helper.GetClientIP(r))
			s.writeConfigState(w)
			return
		}
		if req.Enabled {
			router.JSONError(w, fmt.Sprintf("a port change is still in progress: the old port stays open until every machine has reconnected on the new one (at the latest %s). Close the old port now, or switch the listener off, to change it sooner",
				endsAt.Local().Format("Jan 2 15:04")), http.StatusConflict)
			return
		}
	}

	oldEnabled, oldPort := s.Status()

	// A live port change with agents enrolled migrates gracefully (dual-listen + notify)
	// instead of the hard switch ReloadFromSettings would do (which strands them). Resolve
	// the machine list BEFORE persisting, so a DB error aborts the change cleanly rather
	// than silently downgrading to the stranding path.
	livePortChange := oldEnabled && req.Enabled && req.Port != oldPort
	var toMigrate []Machine
	if livePortChange {
		machines, err := s.enrolledMachines()
		if err != nil {
			router.JSONError(w, "could not list machines to migrate — port change aborted", http.StatusInternalServerError)
			return
		}
		toMigrate = machines
	}

	if err := s.setSettingsTx(map[string]string{
		settingEnabled: boolStr(req.Enabled),
		settingPort:    fmt.Sprintf("%d", req.Port),
	}); err != nil {
		router.JSONError(w, "save failed", http.StatusInternalServerError)
		return
	}

	migrating := false
	if livePortChange && len(toMigrate) > 0 {
		s.beginPortMigration(oldPort, req.Port, toMigrate)
		if err := s.ApplyInstallRoute(); err != nil {
			log.Printf("fleet: install route apply: %v", err)
		}
		migrating = true
	}
	if !migrating {
		s.reloadFromSettingsLocked() // we already hold cfgMu
	}

	s.writeConfigState(w)
}

// writeConfigState answers a config change with the listener's state now.
func (s *Service) writeConfigState(w http.ResponseWriter) {
	enabled, _ := s.Status()
	active, endsAt := s.migrationState()
	router.JSON(w, map[string]any{
		"enabled":         enabled,
		"port":            s.effectivePort(),
		"listening":       enabled,
		"migrating":       active,
		"migrate_ends_at": rfc3339OrEmpty(endsAt),
	})
}

// rfc3339OrEmpty formats a time as RFC3339, or "" for the zero value (so the UI can
// treat an absent migration deadline as "not migrating").
func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

type createTokenRequest struct {
	Label      string `json:"label"`
	TTLSeconds int    `json:"ttl_seconds"`
	PanelHost  string `json:"panel_host"` // direct origin the agent dials for mTLS (IP the operator picked)
}

// handleEndpoints tells the UI the fleet state + the addresses agents can reach the
// panel on, so the Add-Machine dialog can offer WG vs public without env vars.
func (s *Service) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	enabled, _ := s.Status()
	active, endsAt := s.migrationState()
	router.JSON(w, map[string]any{
		"enabled":         enabled,
		"port":            s.effectivePort(),
		"listening":       enabled,
		"domain":          s.sslDomain,        // download domain the install command uses (empty ⇒ none)
		"hosts":           s.HostCandidates(), // addresses the agent could dial for mTLS (operator picks)
		"fingerprint":     s.ca.Fingerprint(),
		"agent_version":   s.agentCache.LatestVersion(r.Context()), // latest published, for "update available"
		"migrating":       active,                                  // a port migration is in flight — lock the port field
		"migrate_ends_at": rfc3339OrEmpty(endsAt),                  // when both ports close down to the new one
	})
}

// handleCheckAgentVersion (POST /api/fleet/agent-version) re-checks the newest published agent
// release now (rate-limited, see RecheckLatestVersion).
func (s *Service) handleCheckAgentVersion(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{"agent_version": s.agentCache.RecheckLatestVersion(r.Context())})
}

func (s *Service) effectivePort() int {
	if _, p := s.Status(); p != 0 {
		return p
	}
	if v := s.getSetting(settingPort); v != "" {
		if p, err := parsePort(v); err == nil {
			return p
		}
	}
	return defaultPort
}

type createTokenResponse struct {
	Token          string    `json:"token"`
	Label          string    `json:"label"`
	ExpiresAt      time.Time `json:"expires_at"`
	CAFingerprint  string    `json:"ca_fingerprint"`
	PanelURL       string    `json:"panel_url"`
	InstallCommand string    `json:"install_command"`
}

// handleCreateToken mints a one-time enrollment token. The plaintext is returned
// ONCE here (the UI shows it inside the install command) and never again.
func (s *Service) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req)
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	// The agent's mTLS channel dials the direct origin the operator picked (an IP);
	// recorded with the token so the install endpoint bakes it into --panel. Default to
	// the first public IP if none was picked.
	panelHost := strings.TrimSpace(req.PanelHost)
	if panelHost == "" {
		panelHost = firstPublicIP()
	}
	tok, err := s.CreateToken(req.Label, ttl, panelHost)
	if err != nil {
		router.JSONError(w, "could not create token", http.StatusInternalServerError)
		return
	}
	// The installer is DOWNLOADED over the panel domain via Traefik/443 (real cert → the
	// command needs no CA handling); the agent then talks mTLS to panelHost:port.
	// Without a domain there's no trusted public cert, so no one-command install is
	// offered (the UI tells the operator to set a domain).
	panelURL, install := "", ""
	if s.sslDomain != "" {
		panelURL = fmt.Sprintf("https://%s:%d", panelHost, s.effectivePort())
		install = fmt.Sprintf(`curl -fsSL "https://%s/agent/%s?arch=$(uname -m)" | sudo sh`, s.sslDomain, tok.Plaintext)
	}
	router.JSON(w, createTokenResponse{
		Token:          tok.Plaintext,
		Label:          tok.Label,
		ExpiresAt:      tok.ExpiresAt,
		CAFingerprint:  s.ca.Fingerprint(),
		PanelURL:       panelURL,
		InstallCommand: install,
	})
}

func (s *Service) handleListMachines(w http.ResponseWriter, r *http.Request) {
	ms, err := s.MachinesFor(r)
	if err != nil {
		router.JSONError(w, "could not list machines", http.StatusInternalServerError)
		return
	}
	router.JSON(w, ms)
}

// MachinesFor lists the machines the request's caller may see: operator/viewer only those in
// their scope, owner/admin all.
func (s *Service) MachinesFor(r *http.Request) ([]Machine, error) {
	ms, err := s.ListMachines()
	if err != nil {
		return nil, err
	}
	return s.filterMachines(r, ms), nil
}

// handleListTokens (GET /api/fleet/tokens) — outstanding enrollment tokens waiting
// for an agent to redeem them. Metadata only; never the token secret.
func (s *Service) handleListTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := s.ListPendingTokens()
	if err != nil {
		router.JSONError(w, "could not list tokens", http.StatusInternalServerError)
		return
	}
	router.JSON(w, toks)
}

// handleDeleteToken (DELETE /api/fleet/tokens?id=<rowid>) cancels an outstanding token.
func (s *Service) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if id <= 0 {
		router.JSONError(w, "id required", http.StatusBadRequest)
		return
	}
	if err := s.DeletePendingToken(id); err != nil {
		router.JSONError(w, "could not cancel token", http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]bool{"ok": true})
}

// handleCAInfo returns the CA fingerprint + PEM (for building install commands).
func (s *Service) handleCAInfo(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{
		"fingerprint": s.ca.Fingerprint(),
		"cert_pem":    string(s.ca.CertPEM()),
	})
}

// handleEnqueueCommand queues an allowlisted command for a machine.
// POST /api/fleet/command  {"machine_id":"...","type":"block","payload":{"ip":"1.2.3.4"}}
func (s *Service) handleEnqueueCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineID       string          `json:"machine_id"`
		Type            string          `json:"type"`
		Payload         json.RawMessage `json:"payload"`
		CurrentPassword string          `json:"currentPassword"` // step-up, for confirm-tier commands
		TotpCode        string          `json:"totpCode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		router.JSONError(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.MachineID == "" {
		router.JSONError(w, "machine_id required", http.StatusBadRequest)
		return
	}
	if !gatePanelInternalCommand(w, r, req.Type) {
		return
	}
	payload, status, err := s.userCommandPayload(req.Type, req.Payload)
	if err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}
	// A rescan's folders to skip are guarded once the request is otherwise good (in scope, online,
	// a valid payload); anything else is refused by enqueueGuarded as usual, without that check
	// running (so no step-up is spent on a request that can't go through).
	var excl *scanExcludeChange
	if req.Type == "rescan" && s.machineAllowed(r, req.MachineID) && linkOnline(req.MachineID) &&
		validateCommandPayload(req.Type, payload) == nil {
		if excl, status, err = s.guardScanExcludes(r, req.MachineID, payload, req.CurrentPassword, req.TotpCode); err != nil {
			router.JSONError(w, err.Error(), status)
			return
		}
	}
	id, status, err := s.enqueueGuarded(r, req.MachineID, req.Type, req.CurrentPassword, req.TotpCode, payload)
	if err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}
	s.auditScanExcludes(r, req.MachineID, excl)
	s.broadcastCommands(req.MachineID) // show the newly-queued command live
	router.JSON(w, map[string]string{"command_id": id})
}

// handleBulkCommand queues one allowlisted command across several machines at once. Step-up is
// verified ONCE (a replay-protected TOTP code can't be reused per host), then each machine goes
// through the same per-machine scope + allowlist + audit checks. Hosts outside the operator's
// scope or that reject the command are reported per-host without failing the whole batch.
// POST /api/fleet/bulk-command  {"machine_ids":["a","b"],"type":"apply-updates","payload":{},"currentPassword":"...","totpCode":"..."}
func (s *Service) handleBulkCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MachineIDs      []string        `json:"machine_ids"`
		Type            string          `json:"type"`
		Payload         json.RawMessage `json:"payload"`
		CurrentPassword string          `json:"currentPassword"`
		TotpCode        string          `json:"totpCode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		router.JSONError(w, "bad json", http.StatusBadRequest)
		return
	}
	if len(req.MachineIDs) == 0 {
		router.JSONError(w, "machine_ids required", http.StatusBadRequest)
		return
	}
	if len(req.MachineIDs) > 500 {
		router.JSONError(w, "too many machines in one request", http.StatusBadRequest)
		return
	}
	if !gatePanelInternalCommand(w, r, req.Type) {
		return
	}
	payload, status, err := s.userCommandPayload(req.Type, req.Payload)
	if err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}
	if req.Type == "rescan" {
		if _, set, _ := parseScanExcludes(payload); set {
			router.JSONError(w, "folders to skip are set per machine, not in a bulk run", http.StatusBadRequest)
			return
		}
	}
	req.Payload = payload
	// Verify step-up once for the whole batch (428 → the UI prompts and retries).
	if status, err := s.verifyCommandStepUp(r, req.Type, req.CurrentPassword, req.TotpCode); err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}

	type result struct {
		MachineID string `json:"machine_id"`
		OK        bool   `json:"ok"`
		CommandID string `json:"command_id,omitempty"`
		Error     string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(req.MachineIDs))
	queued := 0
	for _, id := range req.MachineIDs {
		if id == "" {
			continue
		}
		cid, _, err := s.enqueueCore(r, id, req.Type, req.Payload)
		if err != nil {
			results = append(results, result{MachineID: id, OK: false, Error: err.Error()})
			continue
		}
		results = append(results, result{MachineID: id, OK: true, CommandID: cid})
		queued++
		s.broadcastCommands(id)
	}
	router.JSON(w, map[string]interface{}{"queued": queued, "total": len(results), "results": results})
}

// handleMachineReport returns a machine's latest report JSON.
// GET /api/fleet/report?id=<machine_id>
func (s *Service) handleMachineReport(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		router.JSONError(w, "id required", http.StatusBadRequest)
		return
	}
	if !s.requireMachineAccess(w, r, id) {
		return
	}
	raw, err := s.lastReport(id)
	if err != nil {
		router.JSONError(w, "not found", http.StatusNotFound)
		return
	}
	if raw == "" {
		raw = "null"
	}
	// Bundle the command log so the detail page's first paint is a single request
	// (same shape as the live WS push: { report, commands }).
	cmds, _ := s.ListMachineCommands(id, 20)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"report":   json.RawMessage(raw),
		"commands": cmds,
	})
}
