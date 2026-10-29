package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"api/internal/fleet"

	_ "github.com/mattn/go-sqlite3"
)

func newTestService(t *testing.T) (*Service, *[]string) {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "certs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	sent := &[]string{}
	s.warn = func(tr tracked, level int) { *sent = append(*sent, tr.key+"@"+warnTitle(level)) }
	return s, sent
}

func TestRenewingLevels(t *testing.T) {
	if got := renewingLevels(90 * day); !slices.Equal(got, []int{14, 7, 3, 1, 0}) {
		t.Errorf("90-day cert: %v", got)
	}
	// A 30-day cert renews with 10 days left, so warning at 14 or 7 would fire on every normal renewal.
	if got := renewingLevels(30 * day); !slices.Equal(got, []int{3, 1, 0}) {
		t.Errorf("30-day cert: %v", got)
	}
}

func TestCurrentLevel(t *testing.T) {
	now := time.Now()
	at := func(left time.Duration) tracked { return tracked{notAfter: now.Add(left), levels: autoLevels} }
	for _, c := range []struct {
		left  time.Duration
		level int
		due   bool
	}{
		{20 * day, 0, false},
		{10 * day, 14, true},
		{2 * day, 3, true},
		{-time.Hour, 0, true},
	} {
		if l, due := currentLevel(at(c.left), now); l != c.level || due != c.due {
			t.Errorf("%v left: level %d due %v, want %d %v", c.left, l, due, c.level, c.due)
		}
	}
}

// Each step warns once, a restart doesn't repeat it, a renewed certificate starts over, and the
// rows of certificates that are gone are dropped.
func TestCheckWarnsOncePerStep(t *testing.T) {
	s, sent := newTestService(t)
	now := time.Now()
	cert := tracked{key: "agent:m1", notAfter: now.Add(10 * day), levels: autoLevels}
	run := func(list ...tracked) {
		t.Helper()
		if err := s.checkList(list, now); err != nil {
			t.Fatal(err)
		}
	}
	run(cert)
	run(cert)
	if len(*sent) != 1 {
		t.Fatalf("same step warned %d times: %v", len(*sent), *sent)
	}
	now = now.Add(4 * day) // 6 days left
	run(cert)
	if len(*sent) != 2 || (*sent)[1] != "agent:m1@Certificate expires within 7 days" {
		t.Fatalf("next step: %v", *sent)
	}
	renewed := cert
	renewed.notAfter = now.Add(10 * day) // a new certificate, at the 14-day step again
	run(renewed)
	if len(*sent) != 3 {
		t.Fatalf("a renewed certificate must warn afresh: %v", *sent)
	}
	run() // the machine was removed
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM cert_alerts`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows left for certificates that are gone", n)
	}
}

func TestRenewProblem(t *testing.T) {
	ctx := context.Background()
	if p := renewProblem(ctx, "localhost", "letsencrypt", false); p != "" {
		t.Error("flagged with Cloudflare-only off")
	}
	if p := renewProblem(ctx, "localhost", "letsencrypt-dnschallenge", true); p != "" {
		t.Error("flagged a DNS-challenge certificate")
	}
	if p := renewProblem(ctx, "localhost", "letsencrypt", true); p == "" {
		t.Error("a domain pointing outside Cloudflare wasn't flagged with Cloudflare-only on")
	}
}

// writeACME stores one certificate for domain, expiring in left, as Traefik's acme.json.
func writeACME(t *testing.T, domain string, left time.Duration) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: time.Now().Add(left - 90*day), NotAfter: time.Now().Add(left)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	store := map[string]any{"letsencrypt": map[string]any{"Certificates": []any{
		map[string]any{"domain": map[string]any{"main": domain}, "certificate": base64.StdEncoding.EncodeToString(pemCert)},
	}}}
	b, _ := json.Marshal(store)
	p := filepath.Join(t.TempDir(), "acme.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRAEFIK_ACME", p)
}

// The page lists Traefik's certificates and the panel domains without one, and counts what needs
// attention: a certificate past its renewal point and a domain with no certificate.
func TestOverview(t *testing.T) {
	s, _ := newTestService(t)
	writeACME(t, "site.example", 5*day)
	t.Setenv("SSL_DOMAIN", "panel.example")
	t.Setenv("PROXY_DOMAIN", "")
	o := s.Overview(context.Background())
	if len(o.Websites) != 2 {
		t.Fatalf("websites: %+v", o.Websites)
	}
	var site, panel Website
	for _, w := range o.Websites {
		if w.Domain == "site.example" {
			site = w
		} else {
			panel = w
		}
	}
	if site.Resolver != "letsencrypt" || site.DaysLeft > 5 {
		t.Errorf("site: %+v", site)
	}
	if panel.Domain != "panel.example" || panel.Role != "panel" || panel.Status != "missing" || panel.Problem == "" {
		t.Errorf("panel domain without a certificate: %+v", panel)
	}
	if l, due := o.Due["web:site.example"]; !due || l != 7 {
		t.Errorf("due: %v", o.Due)
	}
	if o.Attention != 2 {
		t.Errorf("attention %d, want 2", o.Attention)
	}
	if o.Fleet != nil {
		t.Error("fleet shown without a fleet service")
	}
}

func TestRenewListenerWithoutFleet(t *testing.T) {
	s, _ := newTestService(t)
	rr := httptest.NewRecorder()
	s.handleRenewListener(rr, httptest.NewRequest(http.MethodPost, "/api/certs/listener/renew", nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("got %d", rr.Code)
	}
}

// Warnings go to admins and owners only, never to operators or viewers.
func TestWarningsOnlyForAdmins(t *testing.T) {
	s, _ := newTestService(t)
	if _, err := s.db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	_, _ = s.db.Exec(`INSERT INTO users (id, role) VALUES (1, 'owner'), (2, 'admin'), (3, 'operator'), (4, 'viewer')`)
	ids, err := s.adminIDs()
	if err != nil || !slices.Equal(ids, []int64{1, 2}) {
		t.Fatalf("recipients %v (%v), want [1 2]", ids, err)
	}
}

// During a CA replacement the old CA's expiry is watched too: the panel still presents it.
func TestTrackedDuringCARotation(t *testing.T) {
	now := time.Now()
	f := &fleet.CertStatus{CA: fleet.CertInfo{NotAfter: now.Add(3650 * day)}, Previous: &fleet.CertInfo{NotAfter: now.Add(20 * day)}, AgentLifetimeDays: 90}
	var prev *tracked
	for _, tr := range trackedList(Overview{Fleet: f}) {
		if tr.key == "fleet-ca-previous" {
			prev = &tr
		}
	}
	if prev == nil {
		t.Fatal("old CA not tracked")
	}
	if l, due := currentLevel(*prev, now); !due || l != 30 {
		t.Fatalf("level %d due %v", l, due)
	}
}
