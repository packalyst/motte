package nftables

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// An isolated (block_all) peer reaches nothing — not other peers or the internet (forward) and
// not the server itself (input: SSH, the host-networked API, DNS, ping). Other peers are untouched.
func TestIsolatedPeerDroppedOnInput(t *testing.T) {
	clients := map[int64]vpnClient{
		1: {ID: 1, Name: "phone", IP: "10.8.0.2", Type: "wireguard", Policy: "selected"},
		2: {ID: 2, Name: "laptop", IP: "10.8.0.3", Type: "wireguard", Policy: "allow_all"},
		3: {ID: 3, Name: "iot", IP: "10.8.0.4", Type: "wireguard", Policy: "block_all"},
		4: {ID: 4, Name: "cam", IP: "100.64.0.9/32", Type: "headscale", Policy: "block_all"},
		5: {ID: 5, Name: "hs-v6", IP: "fd7a:115c:a1e0::5", Type: "headscale", Policy: "block_all"}, // skipped, never wedges
	}
	script := (&VPNACLTable{}).buildScript(clients, nil, nil, "10.8.0.0/24", "100.64.0.0/10", "10.8.0.1")

	set := script[strings.Index(script, "set isolated"):]
	set = set[:strings.Index(set, "}")]
	for _, ip := range []string{"10.8.0.4", "100.64.0.9/32"} {
		if !strings.Contains(set, ip) {
			t.Errorf("isolated set is missing %s:\n%s", ip, set)
		}
	}
	for _, ip := range []string{"10.8.0.2", "10.8.0.3", "fd7a"} {
		if strings.Contains(set, ip) {
			t.Errorf("isolated set holds %s, which isn't an isolated IPv4 peer:\n%s", ip, set)
		}
	}
	for _, rule := range []string{
		"type filter hook input priority 0; policy accept;\n        ip saddr @isolated drop",
		"ip saddr @isolated drop\n        ip daddr @isolated drop",
	} {
		if !strings.Contains(script, rule) {
			t.Errorf("missing %q in:\n%s", rule, script)
		}
	}

	// Syntax-check the whole table when nft is available (CI runners usually lack it).
	nft, err := exec.LookPath("nft")
	if err != nil || os.Geteuid() != 0 {
		t.Skip("nft -c needs nft and root")
	}
	f := filepath.Join(t.TempDir(), "vpn_acl.nft")
	if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(nft, "-c", "-f", f).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "Operation not permitted") {
			t.Skip("nft -c not permitted here (container without CAP_NET_ADMIN)")
		}
		t.Fatalf("nft -c rejected the script: %v\n%s", err, out)
	}
}
