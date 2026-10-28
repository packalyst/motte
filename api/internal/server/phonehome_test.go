package server

import "testing"

// `ss -tunHp state established` output (synthetic addresses) with the `-p`
// process column. Verifies the direction/self-IP logic and process extraction:
// only the genuine external upstreams survive, self + inbound are dropped.
func TestParsePhoneHome(t *testing.T) {
	ss := `tcp 0 0 203.0.113.5:33062 162.159.61.8:443 users:(("adguardhome",pid=100,fd=10))
tcp 0 0 127.0.0.1:35820 127.0.0.1:2375 users:(("dockerd",pid=1,fd=5))
tcp 0 0 127.0.0.1:2375 127.0.0.1:35820 users:(("dockerd",pid=1,fd=6))
tcp 0 0 203.0.113.5:3212 198.51.100.84:63351 users:(("sshd",pid=200,fd=3))
tcp 0 0 203.0.113.5:55428 188.114.97.3:443 users:(("traefik",pid=300,fd=9))
tcp 0 0 203.0.113.5:34478 8.8.4.4:443 users:(("adguardhome",pid=100,fd=11))
tcp 0 0 203.0.113.5:37878 94.140.14.15:443 users:(("adguardhome",pid=100,fd=12))
tcp 0 0 172.19.0.1:44030 172.19.0.2:2375 users:(("dockerd",pid=1,fd=7))
tcp 0 0 203.0.113.5:55670 203.0.113.5:443 users:(("tailscaled",pid=3572380,fd=23))
tcp 0 0 [::ffff:172.17.0.1]:8081 [::ffff:172.18.0.2]:59128 users:(("api",pid=400,fd=8))
tcp 0 0 100.64.0.1:41000 100.100.100.100:443 users:(("tailscaled",pid=3572380,fd=24))`

	listening := map[int]bool{443: true, 2375: true, 8081: true} // 3212 deliberately NOT listed
	ownIPs := map[string]bool{"203.0.113.5": true}

	pb := parsePhoneHome([]byte(ss), listening, ownIPs)

	// Expect exactly the 3 real external upstreams (dedup by ip|port|proc):
	//   162.159.61.8 (adguardhome), 188.114.97.3 (traefik),
	//   8.8.4.4 (adguardhome), 94.140.14.15 (adguardhome)
	want := map[string]string{
		"162.159.61.8": "adguardhome",
		"188.114.97.3": "traefik",
		"8.8.4.4":      "adguardhome",
		"94.140.14.15": "adguardhome",
	}
	if pb.External != len(want) {
		t.Fatalf("external=%d, want %d; got %+v", pb.External, len(want), pb.Destinations)
	}
	got := map[string]string{}
	for _, d := range pb.Destinations {
		got[d.IP] = d.Process
		if d.Port != 443 {
			t.Errorf("%s: port=%d want 443", d.IP, d.Port)
		}
	}
	for ip, proc := range want {
		if got[ip] != proc {
			t.Errorf("%s: process=%q want %q", ip, got[ip], proc)
		}
	}
	// The two confusing rows must NOT appear:
	if _, ok := got["203.0.113.5"]; ok {
		t.Error("self-connection (tailscaled -> own IP) leaked into phone-home")
	}
	if _, ok := got["100.100.100.100"]; ok {
		t.Error("the VPN overlay (100.64.0.0/10) counted as an external host")
	}
	if _, ok := got["198.51.100.84"]; ok {
		t.Error("inbound login (198.51.100.84 -> :3212) mislabeled as outbound")
	}
}

func TestParseProc(t *testing.T) {
	name, pid := parseProc(`tcp 0 0 a:1 b:2 users:(("tailscaled",pid=3572380,fd=23))`)
	if name != "tailscaled" || pid != 3572380 {
		t.Fatalf("got %q/%d", name, pid)
	}
	if n, _ := parseProc("tcp 0 0 a:1 b:2"); n != "" {
		t.Fatalf("no-process line should yield empty, got %q", n)
	}
}

func TestIsEphemeralPort(t *testing.T) {
	if isEphemeralPort(3212) || isEphemeralPort(443) {
		t.Error("service ports must not be ephemeral")
	}
	if !isEphemeralPort(63351) || !isEphemeralPort(55670) {
		t.Error("high client ports must be ephemeral")
	}
}
