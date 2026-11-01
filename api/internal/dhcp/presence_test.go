package dhcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseNeighbors(t *testing.T) {
	nb := parseNeighbors(strings.Join([]string{
		"10.20.20.51 lladdr 02:00:00:00:00:01 REACHABLE",
		"10.20.20.52 lladdr 02:00:00:00:00:02 STALE",
		"10.20.20.53  FAILED",
		"10.20.20.54 lladdr 02:00:00:00:00:04 router DELAY",
		"garbage line",
		"10.20.20.55 lladdr not-a-mac REACHABLE",
		"",
	}, "\n"))
	if !confirmed(nb, "10.20.20.51", "02:00:00:00:00:01") {
		t.Fatal("a REACHABLE entry with the device's MAC is seen")
	}
	for _, c := range []struct{ ip, mac string }{
		{"10.20.20.51", "02:00:00:00:00:99"}, // someone else answering for the address
		{"10.20.20.52", "02:00:00:00:00:02"}, // not confirmed lately
		{"10.20.20.53", ""},                  // never resolved
		{"10.20.20.54", "02:00:00:00:00:04"}, // still being checked
		{"10.20.20.55", ""},                  // unreadable MAC
		{"10.20.20.56", "02:00:00:00:00:06"}, // not in the table
	} {
		if confirmed(nb, c.ip, c.mac) {
			t.Errorf("%s %s must not count as seen", c.ip, c.mac)
		}
	}
}

// presenceTestNet sets up a network whose lease file holds the given lines, with its devices.
func presenceTestNet(t *testing.T, leases ...string) (*Service, *Network) {
	t.Helper()
	s := egressTestService(t)
	dir := t.TempDir()
	prevDir := apiLeaseDir
	apiLeaseDir = dir
	t.Cleanup(func() { apiLeaseDir = prevDir; lastPresence.Store(0) })
	n := &Network{Iface: "ens19", CIDR: "10.20.20.0/24", GatewayIP: "10.20.20.1", PoolStart: "10.20.20.50",
		PoolEnd: "10.20.20.200", LeaseSecs: 3600, Mode: "auto", Enabled: true}
	var err error
	if n.ID, err = s.createNetwork(n); err != nil {
		t.Fatal(err)
	}
	writeLeases(t, n, leases...)
	return s, n
}

func writeLeases(t *testing.T, n *Network, lines ...string) {
	t.Helper()
	if err := os.WriteFile(apiLeasePath(n.Iface), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func stubPresence(t *testing.T, tables ...string) *[]string {
	t.Helper()
	prevRead, prevNudge, prevSettle := readNeighbors, nudgeAddress, presenceSettle
	call := 0
	readNeighbors = func(string) (string, error) {
		if call >= len(tables) {
			return "", errors.New("no table")
		}
		call++
		return tables[call-1], nil
	}
	var nudged []string
	nudgeAddress = func(ip string) { nudged = append(nudged, ip) }
	presenceSettle = 0
	t.Cleanup(func() { readNeighbors, nudgeAddress, presenceSettle = prevRead, prevNudge, prevSettle })
	return &nudged
}

// A round nudges only leased devices inside the network that the kernel hasn't confirmed, then
// marks as seen exactly those answering with their own MAC.
func TestCheckPresence(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	s, n := presenceTestNet(t,
		fmt.Sprintf("%d 02:00:00:00:00:01 10.20.20.51 a *", exp),
		fmt.Sprintf("%d 02:00:00:00:00:02 10.20.20.52 b *", exp),
		fmt.Sprintf("%d 02:00:00:00:00:03 10.20.20.53 c *", exp),
		fmt.Sprintf("%d 02:00:00:00:00:04 10.20.20.54 d *", exp),
		fmt.Sprintf("%d 02:00:00:00:00:05 192.0.2.5 outside *", exp),                // outside the network
		fmt.Sprintf("%d 02:00:00:00:00:06 10.20.20.56 old *", time.Now().Unix()-60), // expired
	)
	s.syncLeases(n)
	// Every device starts long unseen.
	s.db.Exec(`UPDATE dhcp_clients SET last_seen = ?`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	nudged := stubPresence(t,
		"10.20.20.51 lladdr 02:00:00:00:00:01 REACHABLE\n10.20.20.52 lladdr 02:00:00:00:00:02 STALE\n10.20.20.53 lladdr 02:00:00:00:00:99 REACHABLE",
		"10.20.20.51 lladdr 02:00:00:00:00:01 REACHABLE\n10.20.20.52 lladdr 02:00:00:00:00:02 REACHABLE\n10.20.20.53 lladdr 02:00:00:00:00:99 REACHABLE\n10.20.20.54 FAILED",
	)
	if err := s.checkPresence(context.Background()); err != nil {
		t.Fatal(err)
	}
	slices.Sort(*nudged)
	if strings.Join(*nudged, ",") != "10.20.20.52,10.20.20.53,10.20.20.54" {
		t.Fatalf("nudged %v: only leased devices inside the network the kernel hasn't confirmed", *nudged)
	}
	live, err := s.clientsWithLive(n)
	if err != nil {
		t.Fatal(err)
	}
	online := map[string]bool{}
	for _, c := range live {
		online[c.MAC] = c.Online
	}
	if !online["02:00:00:00:00:01"] || !online["02:00:00:00:00:02"] {
		t.Fatalf("answering devices are online: %v", online)
	}
	if online["02:00:00:00:00:03"] || online["02:00:00:00:00:04"] {
		t.Fatalf("a device that doesn't answer (or another MAC answering for it) is offline, lease or not: %v", online)
	}
	if !presenceKnown() {
		t.Fatal("a full round makes presence known")
	}
}

// While presence isn't known (no round yet, or the table unreadable), a lease alone counts.
func TestPresenceUnknownFallsBackToLease(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	s, n := presenceTestNet(t, fmt.Sprintf("%d 02:00:00:00:00:01 10.20.20.51 a *", exp))
	stubPresence(t) // every read fails
	if err := s.checkPresence(context.Background()); err == nil {
		t.Fatal("an unreadable table is an error")
	}
	s.db.Exec(`UPDATE dhcp_clients SET last_seen = ?`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	live, _ := s.clientsWithLive(n)
	if presenceKnown() || len(live) != 1 || !live[0].Online {
		t.Fatalf("unknown presence: lease counts: %+v", live)
	}
}

// A device seen again within presenceWrite isn't rewritten each round.
func TestMarkSeenThrottled(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	s, n := presenceTestNet(t, fmt.Sprintf("%d 02:00:00:00:00:01 10.20.20.51 a *", exp))
	s.syncLeases(n)
	t0 := time.Now().UTC().Truncate(time.Second)
	s.markSeen(n.ID, "02:00:00:00:00:01", t0.Add(-time.Hour))
	s.markSeen(n.ID, "02:00:00:00:00:01", t0)
	s.markSeen(n.ID, "02:00:00:00:00:01", t0.Add(10*time.Second)) // too soon: unchanged
	var got string
	s.db.QueryRow(`SELECT last_seen FROM dhcp_clients`).Scan(&got)
	if got != t0.Format(time.RFC3339) {
		t.Fatalf("last_seen %q, want %q", got, t0.Format(time.RFC3339))
	}
}

// Forgetting an offline device that still holds a lease: it stays forgotten until the lease is
// renewed (it really came back) or runs out; an online one can't be forgotten.
func TestForgetWithLease(t *testing.T) {
	t.Setenv("PATH", "") // the handler re-applies the network: never run ip/iptables on the test host
	exp := time.Now().Add(time.Hour).Unix()
	lease := fmt.Sprintf("%d 02:00:00:00:00:01 10.20.20.51 a *", exp)
	s, n := presenceTestNet(t, lease)
	s.syncLeases(n)
	var id int64
	s.db.QueryRow(`SELECT id FROM dhcp_clients`).Scan(&id)
	forget := func() int {
		rr := httptest.NewRecorder()
		s.handleDeleteClient(rr, httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/dhcp/clients/%d", id), nil))
		return rr.Code
	}
	count := func() int {
		live, _ := s.clientsWithLive(n) // syncs the lease file first
		return len(live)
	}

	// Online (seen just now, presence known): refused.
	lastPresence.Store(time.Now().Unix())
	s.markSeen(n.ID, "02:00:00:00:00:01", time.Now().UTC())
	if code := forget(); code != http.StatusConflict {
		t.Fatalf("forgetting an online device: %d", code)
	}
	// Gone: not seen for a while, lease still running.
	s.db.Exec(`UPDATE dhcp_clients SET last_seen = ?`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	if code := forget(); code != http.StatusOK {
		t.Fatalf("forgetting a gone device: %d", code)
	}
	if c := count(); c != 0 {
		t.Fatalf("the lease file must not bring a forgotten device back: %d", c)
	}
	// It renews its lease: it really came back, so it shows up again.
	writeLeases(t, n, fmt.Sprintf("%d 02:00:00:00:00:01 10.20.20.51 a *", exp+600))
	if c := count(); c != 1 {
		t.Fatalf("a renewed lease brings the device back: %d", c)
	}
	var notes int
	s.db.QueryRow(`SELECT COUNT(*) FROM dhcp_forgotten`).Scan(&notes)
	if notes != 0 {
		t.Fatal("the note goes once the lease is renewed")
	}
	// A note whose lease ran out is dropped.
	s.db.Exec(`INSERT INTO dhcp_forgotten (mac, lease_expiry) VALUES ('02:00:00:00:00:09', ?)`, time.Now().Unix()-10)
	s.forgottenLeases()
	s.db.QueryRow(`SELECT COUNT(*) FROM dhcp_forgotten`).Scan(&notes)
	if notes != 0 {
		t.Fatal("expired notes are cleaned up")
	}
}

// A round stops at once when the api shuts down mid-wait, and leaves no goroutine behind.
func TestPresenceStopsCleanly(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	s, _ := presenceTestNet(t, fmt.Sprintf("%d 02:00:00:00:00:01 10.20.20.51 a *", exp))
	stubPresence(t, "", "")
	presenceSettle = time.Hour
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.checkPresence(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the round did not stop on shutdown")
	}
	time.Sleep(50 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutines: %d before, %d after", before, after)
	}
}
