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
