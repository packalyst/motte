package fleet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"api/internal/router"
)

// signedClientCert issues a client cert from the service CA and returns the parsed cert.
func signedClientCert(t *testing.T, svc *Service, cn string) *x509.Certificate {
	t.Helper()
	_, csrPEM := makeCSR(t, cn)
	b, _ := pem.Decode(csrPEM)
	certPEM, err := svc.ca.SignClientCSR(b.Bytes, cn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(cb.Bytes)
	return cert
}

func withMachine(r *http.Request, m *Machine) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), machineCtxKey, m))
}

// addMachine inserts a machine; online gives it a live link (as if it just dropped within the
// grace period, so no socket is needed), which is what makes a machine accept commands.
func addMachine(t *testing.T, svc *Service, id string, online bool) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := svc.db.Exec(`INSERT INTO fleet_machines (id, name, enrolled_at, last_seen) VALUES (?, ?, ?, ?)`,
		id, id, now, now); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { linkTeardown(id) })
	if online {
		links.Lock()
		links.down[id] = time.Now()
		links.Unlock()
	}
}

// A person's command for an offline machine is refused instead of waiting in the queue to run
// whenever the machine reconnects. Revoked machines are refused too.
func TestEnqueueRefusesOfflineMachine(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "gone", false)
	addMachine(t, svc, "live", true)
	addMachine(t, svc, "revoked", true)
	svc.db.Exec(`UPDATE fleet_machines SET revoked = 1 WHERE id = 'revoked'`)
	linkTeardown("revoked") // what revoking does
	r := httptest.NewRequest("POST", "/api/fleet/command", nil)
	r = r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: "owner", Username: "owner1"}))
	for _, id := range []string{"gone", "revoked", "unknown"} {
		if _, status, err := svc.enqueueCore(r, id, "block", json.RawMessage(`{"ip":"1.2.3.4"}`)); err == nil || status != http.StatusConflict {
			t.Errorf("%s: status=%d err=%v, want 409", id, status, err)
		}
	}
	if _, status, err := svc.enqueueCore(r, "live", "block", json.RawMessage(`{"ip":"1.2.3.4"}`)); err != nil || status != http.StatusOK {
		t.Fatalf("online machine: status=%d err=%v, want ok", status, err)
	}
	var n int
	svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_commands`).Scan(&n)
	if n != 1 {
		t.Fatalf("want only the online machine's command queued, got %d", n)
	}
}

// TestEnqueueGuardrail covers the three guardrail tiers: allow-tier enqueues directly,
// block-tier (not allowlisted) is refused, and confirm-tier without a verifiable operator
// demands step-up (428) instead of enqueuing.
func TestEnqueueGuardrail(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	// An owner principal (unscoped) so the machine-scope check passes and we exercise the
	// role/step-up/allowlist tiers in isolation.
	req := func() *http.Request {
		r := httptest.NewRequest("POST", "/api/fleet/command", nil)
		return r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: "owner", Username: "owner1"}))
	}

	// Allow-tier: enqueued directly.
	id, status, err := svc.enqueueGuarded(req(), "m1", "block", "", "", json.RawMessage(`{"ip":"1.2.3.4"}`))
	if err != nil || status != http.StatusOK || id == "" {
		t.Fatalf("allow-tier block: id=%q status=%d err=%v, want ok", id, status, err)
	}

	// Block-tier: not allowlisted → refused.
	if _, status, err := svc.enqueueGuarded(req(), "m1", "rm-rf-slash", "", "", nil); err == nil || status != http.StatusBadRequest {
		t.Fatalf("block-tier: status=%d err=%v, want 400 + error", status, err)
	}

	// Confirm-tier without a verifiable operator → step-up required (428), not enqueued.
	if _, status, err := svc.enqueueGuarded(req(), "m1", "restart", "", "", nil); err == nil || status != http.StatusPreconditionRequired {
		t.Fatalf("confirm-tier: status=%d err=%v, want 428 + error", status, err)
	}
}

func TestCommandQueueDeliverAckAndReport(t *testing.T) {
	svc := newTestService(t)
	m := Machine{ID: "m1", Name: "web", CertFP: "sha256:aaaa", EnrolledAt: time.Now()}
	if err := svc.registerMachine(m); err != nil {
		t.Fatal(err)
	}

	// enqueue allowlisted; reject non-allowlisted
	cid, err := svc.Enqueue("m1", "block", json.RawMessage(`{"ip":"1.2.3.4"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Enqueue("m1", "rm-rf-slash", nil); err == nil {
		t.Fatal("non-allowlisted command MUST be rejected")
	}

	// deliver once
	rr := httptest.NewRecorder()
	svc.HandleCommands(rr, withMachine(httptest.NewRequest("GET", "/commands", nil), &m))
	var cmds []Command
	_ = json.Unmarshal(rr.Body.Bytes(), &cmds)
	if len(cmds) != 1 || cmds[0].ID != cid || cmds[0].Type != "block" {
		t.Fatalf("bad delivery: %+v", cmds)
	}
	// second poll → nothing (already delivered)
	rr2 := httptest.NewRecorder()
	svc.HandleCommands(rr2, withMachine(httptest.NewRequest("GET", "/commands", nil), &m))
	var cmds2 []Command
	_ = json.Unmarshal(rr2.Body.Bytes(), &cmds2)
	if len(cmds2) != 0 {
		t.Fatalf("delivered command re-served: %+v", cmds2)
	}

	// ack
	ack := withMachine(httptest.NewRequest("POST", "/commands/ack",
		strings.NewReader(`{"results":[{"id":"`+cid+`","ok":true,"output":"blocked"}]}`)), &m)
	svc.HandleCommandAck(httptest.NewRecorder(), ack)
	var status string
	_ = svc.db.QueryRow(`SELECT status FROM fleet_commands WHERE id=?`, cid).Scan(&status)
	if status != "done" {
		t.Fatalf("command status = %q, want done", status)
	}

	// report ingestion
	rep := withMachine(httptest.NewRequest("POST", "/report", strings.NewReader(`{"agent":"x","metrics":{}}`)), &m)
	svc.HandleReport(httptest.NewRecorder(), rep)
	raw, _ := svc.lastReport("m1")
	if !strings.Contains(raw, `"agent":"x"`) {
		t.Fatalf("report not stored: %q", raw)
	}
}

func TestRequireClientCert(t *testing.T) {
	svc := newTestService(t)

	// enroll a machine keyed by a real cert fingerprint
	cert := signedClientCert(t, svc, "agent-1")
	if err := svc.registerMachine(Machine{ID: "m1", CertFP: fingerprintFromCert(cert), EnrolledAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	reached := false
	h := svc.requireClientCert(func(w http.ResponseWriter, r *http.Request) {
		if m := machineFrom(r); m == nil || m.ID != "m1" {
			t.Error("machine not attached")
		}
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	// valid, registered cert -> reaches handler
	req := httptest.NewRequest("POST", "/report", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rr := httptest.NewRecorder()
	h(rr, req)
	if !reached || rr.Code != http.StatusOK {
		t.Fatalf("registered cert should reach handler, got %d", rr.Code)
	}

	// no cert -> 401
	rr2 := httptest.NewRecorder()
	h(rr2, httptest.NewRequest("POST", "/report", nil))
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("no cert should be 401, got %d", rr2.Code)
	}

	// valid CA-signed but UNREGISTERED cert -> 401
	other := signedClientCert(t, svc, "stranger")
	req3 := httptest.NewRequest("POST", "/report", nil)
	req3.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{other}}
	rr3 := httptest.NewRecorder()
	h(rr3, req3)
	if rr3.Code != http.StatusUnauthorized {
		t.Fatalf("unregistered cert should be 401, got %d", rr3.Code)
	}
}

// A person's command not picked up within commandTTL expires and is never delivered; the panel's
// own messages (Enqueue, no expiry) are still delivered however long the machine was away.
func TestCommandExpiry(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	r := httptest.NewRequest("POST", "/api/fleet/command", nil)
	r = r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: "owner", Username: "owner1"}))
	userCmd, _, err := svc.enqueueCore(r, "m1", "block", json.RawMessage(`{"ip":"1.2.3.4"}`))
	if err != nil {
		t.Fatal(err)
	}
	panelMsg, err := svc.Enqueue("m1", "set-console", json.RawMessage(`{"enabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	// The machine was away for an hour: both are old, only the person's command had an expiry.
	old := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	svc.db.Exec(`UPDATE fleet_commands SET created_at = ?, expires_at = CASE WHEN expires_at IS NULL THEN NULL ELSE ? END`, old, old)

	rr := httptest.NewRecorder()
	svc.HandleCommands(rr, withMachine(httptest.NewRequest("GET", "/commands", nil), &Machine{ID: "m1"}))
	var got []Command
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != panelMsg {
		t.Fatalf("want only the panel message delivered, got %+v", got)
	}
	var status string
	svc.db.QueryRow(`SELECT status FROM fleet_commands WHERE id = ?`, userCmd).Scan(&status)
	if status != "expired" {
		t.Fatalf("person's command: status %q, want expired", status)
	}
}

// The command log shows an undelivered command as expired even if the machine never polls again.
func TestCommandLogShowsExpired(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	r := httptest.NewRequest("POST", "/api/fleet/command", nil)
	r = r.WithContext(router.ContextWithPrincipal(r.Context(), &router.Principal{Role: "owner", Username: "owner1"}))
	if _, _, err := svc.enqueueCore(r, "m1", "block", json.RawMessage(`{"ip":"1.2.3.4"}`)); err != nil {
		t.Fatal(err)
	}
	svc.db.Exec(`UPDATE fleet_commands SET expires_at = ?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339))
	cmds, err := svc.ListMachineCommands("m1", 20)
	if err != nil || len(cmds) != 1 || cmds[0].Status != "expired" {
		t.Fatalf("want one expired command, got %+v (%v)", cmds, err)
	}
}

// A machine enrolling with a hostname an active machine already uses gets a numbered name; a revoked
// machine's name is free again, and the result never passes the 64-character limit.
func TestUniqueMachineName(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "a", true)
	svc.db.Exec(`UPDATE fleet_machines SET name = 'web-01' WHERE id = 'a'`)
	addMachine(t, svc, "b", true)
	svc.db.Exec(`UPDATE fleet_machines SET name = 'web-01-2' WHERE id = 'b'`)
	addMachine(t, svc, "c", true)
	svc.db.Exec(`UPDATE fleet_machines SET name = 'old', revoked = 1 WHERE id = 'c'`)
	for in, want := range map[string]string{"web-01": "web-01-3", "WEB-01": "WEB-01-3", "db-01": "db-01", "old": "old"} {
		if got := svc.uniqueMachineName(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("x", 64)
	svc.db.Exec(`UPDATE fleet_machines SET name = ? WHERE id = 'a'`, long)
	if got := svc.uniqueMachineName(long); len(got) > 64 || !strings.HasSuffix(got, "-2") {
		t.Errorf("long name: got %q (%d chars)", got, len(got))
	}
}
