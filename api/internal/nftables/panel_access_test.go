package nftables

import (
	"strings"
	"testing"
)

// The panel-access table can cut the operator's own path into the panel, so pin the
// safety-critical behaviours: fail-OPEN (empty table) when it can't safely restrict, and a
// correct accept-before-drop shape when it can.
func TestPanelAccessBuild_FailsOpen(t *testing.T) {
	// nil db -> restrictEnabled() returns false -> empty shell, never a drop rule.
	tbl := NewPanelAccessTable(nil)
	out, err := tbl.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if strings.Contains(out, "drop") {
		t.Fatalf("fail-open expected: empty table must contain no drop rule:\n%s", out)
	}
	if !strings.Contains(out, "table inet wgadmin_panel_access {\n}") {
		t.Fatalf("expected an empty table shell, got:\n%s", out)
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

func TestTrustedPanelSourcesAlwaysHasLoopback(t *testing.T) {
	// Loopback must always be present so the box can never lock itself out locally.
	got := trustedPanelSources()
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
