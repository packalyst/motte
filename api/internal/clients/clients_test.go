package clients

import (
	"encoding/json"
	"testing"
	"time"

	"api/internal/dhcp"
	"api/internal/fleet"
	"api/internal/vpn"
)

func TestFromVPNFlagsAndIDs(t *testing.T) {
	wg := fromVPN(vpn.VPNClient{Type: "wireguard", ExternalID: "abc", Name: "laptop", IP: "10.8.0.2", BlockInternet: true,
		RawData: json.RawMessage(`{"online":true,"enabled":false,"lastHandshake":"2026-10-22T10:00:00Z"}`)})
	if wg.Key != "wg:abc" || wg.Open.Node != "wg-abc" || !wg.Online || len(wg.Flags) != 2 {
		t.Fatalf("wireguard client mapped wrong: %+v", wg)
	}
	ts := fromVPN(vpn.VPNClient{Type: "headscale", ExternalID: "7", Name: "x", IP: "100.64.0.1",
		RawData: json.RawMessage(`{"givenName":"phone","user":{"name":"ana"},"expiry":"2001-01-01T00:00:00Z","forcedTags":["tag:a"],"validTags":["tag:b","tag:a"]}`)})
	if ts.Name != "phone" || ts.Meta != "ana" || ts.Open.Node != "7" || len(ts.Flags) != 1 || ts.Flags[0].Label != "Key expired" ||
		len(ts.Tags) != 2 || ts.Tags[1] != "tag:b" {
		t.Fatalf("tailscale client mapped wrong: %+v", ts)
	}
	never := fromVPN(vpn.VPNClient{Type: "headscale", ExternalID: "8", RawData: json.RawMessage(`{"expiry":"0001-01-01T00:00:00Z"}`)})
	if len(never.Flags) != 0 {
		t.Fatalf("a never-expiring key must not be flagged: %+v", never.Flags)
	}
}

// A machine is online exactly when the fleet says its link is up — never from report age.
func TestFromMachineOnline(t *testing.T) {
	recent := time.Now().Add(-time.Minute)
	if !fromMachine(&fleet.Machine{ID: "m", Online: true}).Online {
		t.Error("a machine whose link is up is online")
	}
	if fromMachine(&fleet.Machine{ID: "m", LastSeen: &recent}).Online {
		t.Error("a recent report alone does not make a machine online")
	}
}

func TestFromLANPending(t *testing.T) {
	e := fromLAN(dhcp.Network{ID: 3, Iface: "ens19", CIDR: "10.70.70.0/24"}, dhcp.Client{ID: 9, MAC: "aa:bb:cc:dd:ee:ff"})
	if !e.Pending || e.Name != "aa:bb:cc:dd:ee:ff" || e.Open.NetworkID != 3 || e.Open.LanID != 9 {
		t.Fatalf("lan device mapped wrong: %+v", e)
	}
}

// Traffic and last-seen tick constantly; only visible state changes may trigger a refetch.
func TestDigestIgnoresTraffic(t *testing.T) {
	a, b := int64(1), int64(2)
	base := []Client{{Key: "wg:1", Name: "x", Online: true, Tx: &a, LastSeen: "t1"}}
	moved := []Client{{Key: "wg:1", Name: "x", Online: true, Tx: &b, LastSeen: "t2"}}
	if digest(base) != digest(moved) {
		t.Error("traffic/last-seen changes must not change the digest")
	}
	off := []Client{{Key: "wg:1", Name: "x", Online: false, Tx: &a}}
	if digest(base) == digest(off) {
		t.Error("going offline must change the digest")
	}
}

func TestKeyExpiryFlags(t *testing.T) {
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	for _, c := range []struct {
		expiry, want string
	}{
		{"0001-01-01T00:00:00Z", ""},
		{"", ""},
		{at(-time.Hour), "Key expired"},
		{at(3 * time.Hour), "Key expires within a day"},
		{at(4*24*time.Hour - time.Hour), "Key expires in 4 days"},
		{at(14 * 24 * time.Hour), "Key expires in 14 days"},
		{at(15 * 24 * time.Hour), ""},
	} {
		got := ""
		if f := keyExpiryFlags(c.expiry, now); len(f) == 1 {
			got = f[0].Label
		}
		if got != c.want {
			t.Errorf("expiry %q: got %q, want %q", c.expiry, got, c.want)
		}
	}
}
