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

func TestFromMachineOnlineWindow(t *testing.T) {
	recent, old := time.Now().Add(-time.Minute), time.Now().Add(-time.Hour)
	if !fromMachine(&fleet.Machine{ID: "m", LastSeen: &recent}).Online {
		t.Error("a machine that reported a minute ago is online")
	}
	if fromMachine(&fleet.Machine{ID: "m", LastSeen: &old}).Online {
		t.Error("a machine silent for an hour is offline")
	}
	if fromMachine(&fleet.Machine{ID: "m", LastSeen: &recent, Revoked: true}).Online {
		t.Error("a revoked machine is never online")
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
