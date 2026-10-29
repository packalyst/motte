package fleet

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// Re-enrolling gives an existing machine a new certificate, keeping its id, name, tags and history:
// for a machine whose certificate expired while it was offline, or one reinstalled after an
// uninstall. An admin mints a one-time token bound to the machine (after a step-up); the install
// command, run with --force on the machine, wipes the agent's old identity and enrolls with it.
// The old certificate stops working the moment the new one is issued. An expired certificate
// itself is never accepted.

const reenrollTokenTTL = time.Hour

// installCommand is the one-line install for a token, or "" without a panel domain (the installer
// downloads over the domain's HTTPS). extra is appended to the installer's arguments.
func (s *Service) installCommand(token, extra string) string {
	if s.sslDomain == "" {
		return ""
	}
	cmd := fmt.Sprintf(`curl -fsSL "https://%s/agent/%s?arch=$(uname -m)" | sudo sh`, s.sslDomain, token)
	if extra != "" {
		cmd += " -s -- " + extra
	}
	return cmd
}

type reenrollRequest struct {
	MachineID       string `json:"machine_id"`
	PanelHost       string `json:"panel_host"`
	CurrentPassword string `json:"currentPassword"`
	TotpCode        string `json:"totpCode"`
}

// handleReenroll (POST /api/fleet/machine/reenroll {"machine_id"}, admin) mints the machine's
// re-enroll token and returns its install command. It hands out a machine identity, so it takes a
// fresh step-up every time, like deleting a machine.
func (s *Service) handleReenroll(w http.ResponseWriter, r *http.Request) {
	var req reenrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		router.JSONError(w, "invalid request", http.StatusBadRequest)
		return
	}
	var name string // uninstalled machines included: reinstalling one is what this is for
	if err := s.db.QueryRow(`SELECT name FROM fleet_machines WHERE id = ?`, req.MachineID).Scan(&name); err != nil {
		router.JSONError(w, "machine not found", http.StatusNotFound)
		return
	}
	if s.sslDomain == "" {
		router.JSONError(w, "set a panel domain (SSL_DOMAIN) first: the installer downloads over its HTTPS", http.StatusConflict)
		return
	}
	if status, err := s.consoleStepUp(r, req.CurrentPassword, req.TotpCode); err != nil {
		router.JSONError(w, err.Error(), status)
		return
	}
	panelHost := strings.TrimSpace(req.PanelHost)
	if panelHost == "" {
		panelHost = firstPublicIP()
	}
	tok, err := s.CreateToken("Re-enroll "+name, reenrollTokenTTL, panelHost, req.MachineID)
	if err != nil {
		router.JSONError(w, "could not create token", http.StatusInternalServerError)
		return
	}
	actor, _ := s.actingAdmin(r)
	events.Audit("fleet", "reenroll_token_issued", events.SeverityWarning, actor, helper.GetClientIP(r),
		fmt.Sprintf("Re-enroll command issued for machine %s (%s), valid one hour", name, req.MachineID))
	router.JSON(w, map[string]any{"install_command": s.installCommand(tok.Plaintext, "--force"), "expires_at": tok.ExpiresAt})
}

// reenroll finishes /enroll for a token bound to machine id: signs the CSR for that id and makes
// the new certificate the machine's only one, reactivating it if it was uninstalled. The agent's
// live link and console (on the old certificate) are dropped.
func (s *Service) reenroll(w http.ResponseWriter, r *http.Request, id string, csrDER []byte, req enrollRequest) {
	certPEM, err := s.ca.SignClientCSR(csrDER, id, s.clientCertTTL())
	if err != nil {
		log.Printf("fleet: re-enroll csr rejected: %v", err)
		writeErr(w, http.StatusBadRequest, "csr rejected")
		return
	}
	notAfter, err := certNotAfterPEM(certPEM)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server error")
		return
	}
	var name string
	err = s.withMachineTx(id, func(tx *sql.Tx) error {
		if err := tx.QueryRow(`SELECT name FROM fleet_machines WHERE id = ?`, id).Scan(&name); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE fleet_machines SET cert_fp = ?, cert_expires = ?, cert_fp_next = NULL, cert_expires_next = NULL,
			machine_hash = ?, wg_pubkey = ?, revoked = 0, status = 'enrolled' WHERE id = ?`,
			certFingerprintPEM(certPEM), notAfter.UTC().Format(time.RFC3339), machineIdentityHash(req.MachineID, req.WGPubkey), req.WGPubkey, id)
		return err
	})
	if err != nil {
		// The machine was removed after the token was issued: nothing to re-enroll.
		writeErr(w, http.StatusUnauthorized, "invalid or used enrollment token")
		return
	}
	events.Audit("fleet", "machine_reenrolled", events.SeverityWarning, name, helper.GetClientIP(r),
		fmt.Sprintf("Machine %s (%s) re-enrolled with a new certificate (valid until %s); the previous one no longer works", name, id, notAfter.UTC().Format(time.DateOnly)))
	writeJSON(w, http.StatusOK, enrollResponse{MachineID: id, ClientCert: string(certPEM), CACert: string(s.ca.CertPEM())})
}
