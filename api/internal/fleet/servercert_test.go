package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"slices"
	"testing"
	"time"
)

// The listener certificate is made once and reused, lasts serverCertTTL, carries the panel domain
// and chains to the panel CA.
func TestServerCertCachedAndValid(t *testing.T) {
	svc := newTestService(t)
	a, err := svc.serverCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := svc.serverCertificate(nil)
	if a != b {
		t.Fatal("a fresh certificate must be reused, not minted per handshake")
	}
	if left := time.Until(a.Leaf.NotAfter); left < serverCertTTL-time.Hour || left > serverCertTTL {
		t.Fatalf("lifetime %v, want about %v", left, serverCertTTL)
	}
	if _, err := a.Leaf.Verify(x509.VerifyOptions{DNSName: "panel.example", Roots: svc.ca.Pool()}); err != nil {
		t.Fatalf("doesn't verify for the panel domain against the CA: %v", err)
	}
}

// A certificate inside the renewal window is replaced.
func TestServerCertRenewsNearExpiry(t *testing.T) {
	svc := newTestService(t)
	old, err := svc.serverCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	short, err := svc.ca.ServerCertificate(svc.srvCert.hosts, serverCertRenewAt-time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	svc.srvCert.cert = &short
	got, _ := svc.serverCertificate(nil)
	if got == &short || got == old || time.Until(got.Leaf.NotAfter) < serverCertTTL-time.Hour {
		t.Fatal("a certificate close to expiry wasn't renewed")
	}
}

// A change of the host's addresses or domain is picked up at the next recheck, not before.
func TestServerCertFollowsHostChange(t *testing.T) {
	svc := newTestService(t)
	cur, err := svc.serverCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.srvCert.hosts = []string{"203.0.113.9"} // what the cert was "made for" before the IP changed
	if got, _ := svc.serverCertificate(nil); got != cur {
		t.Fatal("re-read the host's addresses before the recheck interval")
	}
	svc.srvCert.checked = time.Now().Add(-serverCertRecheck)
	got, _ := svc.serverCertificate(nil)
	if got == cur || slices.Contains(svc.srvCert.hosts, "203.0.113.9") {
		t.Fatal("a host change wasn't picked up")
	}
}

// The listener's TLS config serves the managed certificate: an agent trusting only the CA connects.
func TestListenerServesManagedCert(t *testing.T) {
	svc := newTestService(t)
	tc, err := svc.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tc)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: svc.ca.Pool(), ServerName: "panel.example", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("agent-side handshake failed: %v", err)
	}
	defer conn.Close()
	if conn.ConnectionState().PeerCertificates[0].SerialNumber.Cmp(svc.srvCert.cert.Leaf.SerialNumber) != 0 {
		t.Fatal("listener didn't serve the managed certificate")
	}
}

// "Renew now" replaces the certificate even when it isn't due.
func TestRenewListenerCertForces(t *testing.T) {
	svc := newTestService(t)
	old, err := svc.serverCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RenewListenerCert(); err != nil {
		t.Fatal(err)
	}
	if cur, _ := svc.currentListenerCert(); cur == old || cur.Leaf.SerialNumber.Cmp(old.Leaf.SerialNumber) == 0 {
		t.Fatal("Renew now kept the old certificate")
	}
}

// The certificate status lists the CA, the listener only while it runs, and the client certificates
// of enrolled (not revoked) machines, soonest first.
func TestCertStatus(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.serverCertificate(nil); err != nil {
		t.Fatal(err)
	}
	addMachine(t, svc, "late", false)
	addMachine(t, svc, "soon", false)
	addMachine(t, svc, "gone", false)
	addMachine(t, svc, "new", false) // no certificate recorded yet
	now := time.Now().UTC()
	for id, left := range map[string]time.Duration{"late": 60 * 24 * time.Hour, "soon": 5 * 24 * time.Hour, "gone": time.Hour} {
		_, _ = svc.db.Exec(`UPDATE fleet_machines SET cert_expires = ? WHERE id = ?`, now.Add(left).Format(time.RFC3339), id)
	}
	_, _ = svc.db.Exec(`UPDATE fleet_machines SET revoked = 1 WHERE id = 'gone'`)

	st, err := svc.CertStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.CA.Fingerprint != svc.ca.Fingerprint() || st.AgentLifetimeDays != 90 {
		t.Errorf("CA/lifetime: %+v", st)
	}
	if st.Listener != nil {
		t.Error("listener shown while it's off")
	}
	if len(st.Agents) != 2 || st.Agents[0].MachineID != "soon" || st.Agents[1].MachineID != "late" {
		t.Fatalf("agents: %+v", st.Agents)
	}
	svc.mu.Lock()
	svc.enabled = true
	svc.mu.Unlock()
	if st, _ = svc.CertStatus(); st.Listener == nil || st.Listener.Fingerprint != fingerprintFromCert(svc.srvCert.cert.Leaf) {
		t.Fatalf("listener while on: %+v", st.Listener)
	}
}
