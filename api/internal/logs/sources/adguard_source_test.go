package sources

import (
	"os"
	"path/filepath"
	"testing"
)

// A DNS log row names what decided it: the blocklist by its name in AdGuardHome.yaml, the
// user's own rules, a blocked service or one of AdGuard's protections.
func TestRuleSource(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "AdGuardHome.yaml")
	if err := os.WriteFile(conf, []byte("filters:\n  - enabled: true\n    url: https://lists.example.test/ads.txt\n    name: Example Ads List\n    id: 1700000001\nwhitelist_filters: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &AdGuardWatcher{filters: filterNames{path: conf}}
	rule := func(id int) []AdGuardRule { return []AdGuardRule{{Text: "||ads.example.test^", FilterListID: id}} }
	for _, c := range []struct {
		res  AdGuardResult
		want string
	}{
		{AdGuardResult{IsFiltered: true, Reason: ReasonFiltered, Rules: rule(1700000001)}, "Example Ads List"},
		{AdGuardResult{IsFiltered: true, Reason: ReasonFiltered, Rules: rule(customRulesID)}, "Custom rule"},
		{AdGuardResult{IsFiltered: true, Reason: ReasonFiltered, Rules: rule(42)}, "Blocklist 42"},
		{AdGuardResult{IsFiltered: true, Reason: ReasonBlockedService, ServiceName: "tiktok"}, "Blocked service: tiktok"},
		{AdGuardResult{IsFiltered: true, Reason: ReasonParental}, "Parental control"},
		{AdGuardResult{IsFiltered: true, Reason: ReasonSafeBrowsing}, "Safe browsing"},
		{AdGuardResult{Reason: ReasonRewritten}, "DNS rewrite"},
		{AdGuardResult{Reason: ReasonNotFiltered}, ""},
	} {
		if got := w.ruleSource(AdGuardLogEntry{Result: c.res}); got != c.want {
			t.Errorf("reason %d: got %q, want %q", c.res.Reason, got, c.want)
		}
	}
}

func TestRuleSourceWithoutConfig(t *testing.T) {
	w := &AdGuardWatcher{}
	got := w.ruleSource(AdGuardLogEntry{Result: AdGuardResult{IsFiltered: true, Reason: ReasonFiltered, Rules: []AdGuardRule{{FilterListID: 7}}}})
	if got != "Blocklist 7" {
		t.Fatalf("got %q", got)
	}
}
