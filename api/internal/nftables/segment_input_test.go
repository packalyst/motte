package nftables

import (
	"strings"
	"testing"
)

// segmentInputRules must open DHCP and DNS scoped to each managed NIC, and nothing for a blank name.
func TestSegmentInputRules(t *testing.T) {
	got := strings.Join(segmentInputRules([]string{"ens19", "  ", ""}), "\n")

	if !strings.Contains(got, `iifname "ens19" udp dport 67 accept`) {
		t.Fatalf("missing scoped DHCP rule in:\n%s", got)
	}

	if !strings.Contains(got, `iifname "ens19" meta l4proto { tcp, udp } th dport 53 accept`) {
		t.Fatalf("missing scoped DNS rule in:\n%s", got)
	}

	// Every port rule MUST be interface-scoped (an unscoped dport accept would hit the WAN too).
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue // comment
		}
		if strings.Contains(line, "dport") && !strings.Contains(line, `iifname "ens19"`) {
			t.Fatalf("port rule not scoped to an interface: %q", line)
		}
	}

	// Blank interface names contribute no rules.
	if n := len(segmentInputRules([]string{"", "   "})); n != 0 {
		t.Fatalf("blank ifaces should emit no rules, got %d lines", n)
	}
}
