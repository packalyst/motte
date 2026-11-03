package nftables

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"api/internal/database"

	_ "github.com/mattn/go-sqlite3"
)

// The cf_only table can cut off ALL web access, so pin the safety-critical behaviours:
// fail-OPEN (empty table) when disabled, and a correct accept-before-drop shape when on.

func TestCloudflareOnlyBuild_FailsOpen(t *testing.T) {
	// nil db -> restrictEnabled() false -> empty shell, never a drop rule.
	out, err := NewCloudflareOnlyTable(nil).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if strings.Contains(out, "drop") {
		t.Fatalf("fail-open expected: empty table must contain no drop:\n%s", out)
	}
	if !strings.Contains(out, "table inet motte_cf_only {\n}") {
		t.Fatalf("expected an empty table shell, got:\n%s", out)
	}
}

func cfTestDB(t *testing.T, val string) *database.DB {
	t.Helper()
	raw, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, encrypted INTEGER DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if val != "" {
		if _, err := raw.Exec(`INSERT INTO settings (key,value,encrypted) VALUES ('web_cloudflare_only',?,0)`, val); err != nil {
			t.Fatal(err)
		}
	}
	return &database.DB{DB: raw}
}

func TestCloudflareOnlyBuild_OffIsEmptyShell(t *testing.T) {
	out, _ := NewCloudflareOnlyTable(cfTestDB(t, "off")).Build()
	if strings.Contains(out, "drop") {
		t.Fatalf("off must be an empty shell (no drop), got:\n%s", out)
	}
}

func TestCloudflareOnlyBuild_Enabled(t *testing.T) {
	out, err := NewCloudflareOnlyTable(cfTestDB(t, "on")).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// References the Cloudflare set, keeps loopback trusted, and drops the web ports.
	for _, want := range []string{"set cf_v4", "@cf_v4", "127.0.0.0/8", "tcp dport 443 drop"} {
		if !strings.Contains(out, want) {
			t.Errorf("enabled build missing %q:\n%s", want, out)
		}
	}
	// MUST filter both hooks: input (host-networked) AND forward (Docker-published
	// Traefik traffic is DNAT'd and forwarded, so an input-only rule would miss it).
	if !strings.Contains(out, "hook input") || !strings.Contains(out, "hook forward") {
		t.Errorf("expected both input and forward chains:\n%s", out)
	}
	// The forward rules must be scoped to DNAT'd (externally-published) traffic only.
	if !strings.Contains(out, "ct status dnat tcp dport 443 drop") {
		t.Errorf("forward drop must be scoped to ct status dnat:\n%s", out)
	}
	// Never-lock-out invariant: the accept rules MUST precede the drop.
	firstAccept := strings.Index(out, "accept")
	drop := strings.Index(out, "tcp dport 443 drop")
	if firstAccept == -1 || drop == -1 || firstAccept > drop {
		t.Fatalf("accepts must precede the drop (accept=%d drop=%d):\n%s", firstAccept, drop, out)
	}
}

// Regression (2026-10-17): a TRANSIENT DB read error must NOT strip Cloudflare-only
// protection. restrictEnabled keeps the last-known-restrictive state on any error that isn't
// sql.ErrNoRows; previously a read error fell through to "off", silently exposing 80/443.
func TestCloudflareOnlyBuild_FailsClosedOnDBError(t *testing.T) {
	db := cfTestDB(t, "on")
	tbl := NewCloudflareOnlyTable(db)

	// Prime the last-known state to "restricted".
	out, err := tbl.Build()
	if err != nil {
		t.Fatalf("initial Build: %v", err)
	}
	if !strings.Contains(out, "tcp dport 443 drop") {
		t.Fatalf("precondition: an enabled build must drop the web ports:\n%s", out)
	}

	// Make the settings read fail with a non-ErrNoRows error, leaving the handle open so
	// only restrictEnabled is affected.
	if _, err := db.DB.Exec(`DROP TABLE settings`); err != nil {
		t.Fatalf("drop settings: %v", err)
	}

	out2, err := tbl.Build()
	if err != nil {
		t.Fatalf("Build after a DB error must not itself error: %v", err)
	}
	if !strings.Contains(out2, "tcp dport 443 drop") {
		t.Fatalf("fail-CLOSED expected: a transient DB error must keep the drop, got:\n%s", out2)
	}
}

func TestSplitCIDRs(t *testing.T) {
	v4, v6 := splitCIDRs([]string{"1.2.3.0/24", "2606:4700::/32", "104.16.0.0/13"})
	if len(v4) != 2 || len(v6) != 1 {
		t.Fatalf("split wrong: v4=%v v6=%v", v4, v6)
	}
}

func TestValidCIDROr(t *testing.T) {
	if got := validCIDROr("10.0.0.0/8", "1.1.1.0/24"); got != "10.0.0.0/8" {
		t.Errorf("valid value should pass through, got %q", got)
	}
	if got := validCIDROr("not-a-cidr", "172.18.0.0/24"); got != "172.18.0.0/24" {
		t.Errorf("invalid value should fall back, got %q", got)
	}
	if got := validCIDROr("", "10.8.0.0/16"); got != "10.8.0.0/16" {
		t.Errorf("empty value should fall back, got %q", got)
	}
}

func TestTrustedAdminSourcesAlwaysHasLoopback(t *testing.T) {
	// Loopback must always be present so the box can never lock itself out locally.
	got := TrustedAdminSources()
	var hasLoopback bool
	for _, c := range got {
		if c == "127.0.0.0/8" {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		t.Fatalf("trusted sources must always include loopback; got %v", got)
	}
	if len(got) < 2 {
		t.Fatalf("expected loopback + docker/WG fallbacks, got %v", got)
	}
}

// Port 80 is never filtered by the kernel (Let's Encrypt must reach it; Traefik gates it), and
// WebGateSources gives the gate the same sources the 443 rule accepts — nothing when off.
func TestCloudflareOnlyLeavesPort80ToTheGate(t *testing.T) {
	out, _ := NewCloudflareOnlyTable(cfTestDB(t, "on")).Build()
	if strings.Contains(out, "dport 80") || strings.Contains(out, "dport { 80") {
		t.Fatalf("the kernel rule must not touch port 80:\n%s", out)
	}
	if got := NewCloudflareOnlyTable(cfTestDB(t, "off")).WebGateSources(); got != nil {
		t.Fatalf("off: gate sources %v, want nil (everyone)", got)
	}
	got := NewCloudflareOnlyTable(cfTestDB(t, "on")).WebGateSources()
	has := map[string]bool{}
	for _, c := range got {
		has[c] = true
	}
	for _, want := range append([]string{"127.0.0.0/8", "::1/128", "104.16.0.0/13"}, TrustedAdminSources()...) {
		if !has[want] {
			t.Errorf("gate sources missing %q: %v", want, got)
		}
	}
}

// With Cloudflare-only on, a LAN device let in to a private domain route still reaches HTTPS, on
// its own LAN interface and address only; a malformed interface name is never written.
func TestCloudflareOnlyBuild_LANRouteDevices(t *testing.T) {
	db := cfTestDB(t, "on")
	if _, err := db.DB.Exec(`
		CREATE TABLE dhcp_networks (id INTEGER PRIMARY KEY, iface TEXT, cidr TEXT, enabled INTEGER);
		CREATE TABLE dhcp_clients (id INTEGER PRIMARY KEY, network_id INTEGER, ip TEXT, mac TEXT, approved INTEGER, blocked INTEGER);
		CREATE TABLE domain_routes (id INTEGER PRIMARY KEY, domain TEXT, enabled INTEGER, access_mode TEXT, lan_all INTEGER);
		CREATE TABLE domain_route_lan_devices (route_id INTEGER, device_id INTEGER);
		INSERT INTO dhcp_networks VALUES (1, 'ens19', '10.20.20.0/24', 1), (2, 'ens20" accept', '10.30.30.0/24', 1);
		INSERT INTO dhcp_clients VALUES (1, 1, '10.20.20.51', '02:00:00:00:00:01', 1, 0), (2, 2, '10.30.30.51', '02:00:00:00:00:02', 1, 0);
		INSERT INTO domain_routes VALUES (1, 'git.example.com', 1, 'vpn', 1)`); err != nil {
		t.Fatal(err)
	}
	out, err := NewCloudflareOnlyTable(db).Build()
	if err != nil {
		t.Fatal(err)
	}
	// Each chain (input, then forward) lets the device in above its own drop.
	for _, c := range []struct{ accept, drop string }{
		{`iifname "ens19" ip saddr 10.20.20.51 tcp dport 443 accept`, "\n        tcp dport 443 drop"},
		{`ct status dnat iifname "ens19" ip saddr 10.20.20.51 tcp dport 443 accept`, "ct status dnat tcp dport 443 drop"},
	} {
		if at, drop := strings.Index(out, c.accept), strings.Index(out, c.drop); at < 0 || drop < 0 || at > drop {
			t.Errorf("missing %q above %q:\n%s", c.accept, c.drop, out)
		}
	}
	if strings.Contains(out, "10.30.30.51") {
		t.Errorf("a malformed interface name was written:\n%s", out)
	}
	nftCheck(t, out)
}
