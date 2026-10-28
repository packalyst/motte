package nftables

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"api/internal/database"
)

// setBlock returns the text of one set definition in a generated script.
func setBlock(t *testing.T, script, name string) string {
	t.Helper()
	i := strings.Index(script, "set "+name+" {")
	if i < 0 {
		t.Fatalf("set %s missing", name)
	}
	j := strings.Index(script[i:], "}")
	return script[i : i+j]
}

// TestAPIPortAlwaysPrivate: the panel API port lands in the private (off-WAN) set even when its
// stored scope says public (a restored backup, a hand edit); other ports keep their scope.
func TestAPIPortAlwaysPrivate(t *testing.T) {
	t.Setenv("API_PORT", "18081")
	db, err := database.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM firewall_entries`); err != nil {
		t.Fatal(err)
	}
	for _, port := range []string{"18081", "2222"} {
		if _, err := db.Exec(`INSERT INTO firewall_entries (entry_type, value, action, direction, protocol, source, scope, enabled)
			VALUES ('port', ?, 'allow', 'inbound', 'tcp', 'system', 'public', 1)`, port); err != nil {
			t.Fatal(err)
		}
	}
	script, err := NewFirewallTable(db, nil, nil).Build()
	if err != nil {
		t.Fatal(err)
	}
	public, private := setBlock(t, script, "allowed_tcp_ports"), setBlock(t, script, "allowed_tcp_ports_private")
	if strings.Contains(public, "18081") || !strings.Contains(private, "18081") {
		t.Errorf("API port must be private only:\npublic: %s\nprivate: %s", public, private)
	}
	if !strings.Contains(public, "2222") || strings.Contains(private, "2222") {
		t.Errorf("another public port lost its scope:\npublic: %s\nprivate: %s", public, private)
	}
}

// TestPrivatePortsWithoutWAN: with the WAN undetected, private ports still accept the Docker
// network (Traefik → panel API) besides loopback and the VPN, and the script stays valid.
func TestPrivatePortsWithoutWAN(t *testing.T) {
	t.Setenv("DOCKER_SUBNET", "172.30.0.0/24")
	rules := strings.Join(privatePortRules(""), "\n")
	if !strings.Contains(rules, "ip saddr 172.30.0.0/24 tcp dport @allowed_tcp_ports_private accept") {
		t.Errorf("Docker network missing from the WAN-undetected fallback:\n%s", rules)
	}
	script := (&FirewallTable{}).buildScript(scriptParams{tcpPorts: []string{"443"}, tcpPortsPrivate: []string{"8081"}})

	nft, err := exec.LookPath("nft")
	if err != nil || os.Geteuid() != 0 {
		t.Skip("nft -c needs nft and root")
	}
	f := filepath.Join(t.TempDir(), "firewall.nft")
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
