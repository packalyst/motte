package fleet

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// enrollWith posts /enroll with token, as a fresh agent would.
func enrollWith(t *testing.T, svc *Service, token string) *httptest.ResponseRecorder {
	t.Helper()
	_, csrPEM := makeCSR(t, "agent")
	body, _ := json.Marshal(enrollRequest{Token: token, CSR: string(csrPEM), MachineID: "machineid-new", Hostname: "renamed-host"})
	rr := httptest.NewRecorder()
	svc.HandleEnroll(rr, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body)))
	return rr
}

// A re-enroll token gives the SAME machine a new certificate: same id and name, history kept,
// reactivated after an uninstall; its previous certificate stops working.
func TestReenrollKeepsMachine(t *testing.T) {
	useRecordStore(t)
	svc := newTestService(t)
	old, oldPEM := issueCert(t, svc, "m1", 90*24*time.Hour)
	if err := svc.registerMachine(Machine{ID: "m1", Name: "web-01", CertFP: certFingerprintPEM(oldPEM), EnrolledAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	seedMachineData(t, svc, "m1")
	if err := svc.MarkUninstalled("m1"); err != nil {
		t.Fatal(err)
	}
	tok, err := svc.CreateToken("Re-enroll web-01", time.Hour, "", "m1")
	if err != nil {
		t.Fatal(err)
	}
	rr := enrollWith(t, svc, tok.Plaintext)
	if rr.Code != http.StatusOK {
		t.Fatalf("re-enroll: %d %s", rr.Code, rr.Body)
	}
	var resp enrollResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	b, _ := pem.Decode([]byte(resp.ClientCert))
	if resp.MachineID != "m1" || b == nil {
		t.Fatalf("re-enroll answered for %q", resp.MachineID)
	}

	var n int
	_ = svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_machines`).Scan(&n)
	var name, status, fp string
	var revoked int
	_ = svc.db.QueryRow(`SELECT name, status, revoked, cert_fp FROM fleet_machines WHERE id = 'm1'`).Scan(&name, &status, &revoked, &fp)
	if n != 1 || name != "web-01" || status != "enrolled" || revoked != 0 || fp != certFingerprintPEM([]byte(resp.ClientCert)) {
		t.Fatalf("machines=%d name=%q status=%q revoked=%d", n, name, status, revoked)
	}
	if rowsFor(t, svc, "m1") != len(machineDataTables) {
		t.Fatal("re-enroll lost the machine's history")
	}
	if m, _ := svc.machineByCertFP(fingerprintFromCert(old)); m != nil {
		t.Fatal("the previous certificate still works")
	}
	if rr := enrollWith(t, svc, tok.Plaintext); rr.Code != http.StatusUnauthorized {
		t.Fatalf("token reused: %d", rr.Code)
	}
}

// A re-enroll token for a machine removed in the meantime enrolls nothing.
func TestReenrollRemovedMachine(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "gone", false)
	tok, _ := svc.CreateToken("Re-enroll gone", time.Hour, "", "gone")
	if err := svc.DeleteMachine("gone"); err != nil {
		t.Fatal(err)
	}
	if rr := enrollWith(t, svc, tok.Plaintext); rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rr.Code)
	}
	var n int
	_ = svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_machines`).Scan(&n)
	if n != 0 {
		t.Fatal("a machine was created from a re-enroll token")
	}
}

// Issuing a re-enroll command needs the machine to exist and a fresh password.
func TestReenrollEndpointGates(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", false)
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		svc.handleReenroll(rr, httptest.NewRequest(http.MethodPost, "/api/fleet/machine/reenroll", strings.NewReader(body)))
		return rr
	}
	if rr := post(`{"machine_id":"nope"}`); rr.Code != http.StatusNotFound {
		t.Errorf("unknown machine: %d", rr.Code)
	}
	if rr := post(`{"machine_id":"m1"}`); rr.Code != http.StatusPreconditionRequired {
		t.Errorf("no password: %d", rr.Code)
	}
	var n int
	_ = svc.db.QueryRow(`SELECT COUNT(*) FROM fleet_tokens`).Scan(&n)
	if n != 0 {
		t.Fatal("a token was minted without a step-up")
	}
	if cmd := svc.installCommand("TOK", "--force"); !strings.HasSuffix(cmd, `/agent/TOK?arch=$(uname -m)" | sudo sh -s -- --force`) {
		t.Errorf("install command: %s", cmd)
	}
}

// The lifetime setting drives new certificates, falls back to 90 days on anything else, and only
// changes with a step-up.
func TestCertLifetime(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.db.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, encrypted INTEGER DEFAULT 0, updated_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	set := func(v string) {
		t.Helper()
		if err := svc.setSettingsTx(map[string]string{certDaysSetting: v}); err != nil {
			t.Fatal(err)
		}
	}
	if svc.certDays() != 90 {
		t.Fatalf("default %d", svc.certDays())
	}
	set("45")
	if svc.certDays() != 90 {
		t.Fatal("a value outside the choices was used")
	}
	set("30")
	tok, _ := svc.CreateToken("x", time.Hour, "", "")
	rr := enrollWith(t, svc, tok.Plaintext)
	var resp enrollResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	nb, err := certNotAfterPEM([]byte(resp.ClientCert))
	if err != nil || time.Until(nb) > 30*24*time.Hour || time.Until(nb) < 29*24*time.Hour {
		t.Fatalf("enrolled cert expires %v, want in 30 days", nb)
	}

	post := func(body string) int {
		rr := httptest.NewRecorder()
		svc.handleCertLifetime(rr, httptest.NewRequest(http.MethodPost, "/api/fleet/cert-lifetime", strings.NewReader(body)))
		return rr.Code
	}
	if code := post(`{"days":45}`); code != http.StatusBadRequest {
		t.Errorf("invalid days: %d", code)
	}
	if code := post(`{"days":365}`); code != http.StatusPreconditionRequired {
		t.Errorf("no password: %d", code)
	}
	if svc.certDays() != 30 {
		t.Fatal("changed without a step-up")
	}
}
