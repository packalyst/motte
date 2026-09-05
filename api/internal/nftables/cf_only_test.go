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
	if !strings.Contains(out, "table inet wgadmin_cf_only {\n}") {
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
	for _, want := range []string{"set cf_v4", "@cf_v4", "127.0.0.0/8", "tcp dport { 80, 443 } drop"} {
		if !strings.Contains(out, want) {
			t.Errorf("enabled build missing %q:\n%s", want, out)
		}
	}
	// Never-lock-out invariant: the accept rules MUST precede the drop.
	firstAccept := strings.Index(out, "accept")
	drop := strings.Index(out, "tcp dport { 80, 443 } drop")
	if firstAccept == -1 || drop == -1 || firstAccept > drop {
		t.Fatalf("accepts must precede the drop (accept=%d drop=%d):\n%s", firstAccept, drop, out)
	}
}

func TestSplitCIDRs(t *testing.T) {
	v4, v6 := splitCIDRs([]string{"1.2.3.0/24", "2606:4700::/32", "104.16.0.0/13"})
	if len(v4) != 2 || len(v6) != 1 {
		t.Fatalf("split wrong: v4=%v v6=%v", v4, v6)
	}
}
