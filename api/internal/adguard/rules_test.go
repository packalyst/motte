package adguard

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// httptestFiltering runs one /api/adguard/filtering request through s.
func httptestFiltering(s *Service, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.handleFilteringAction(w, httptest.NewRequest("PUT", "/api/adguard/filtering", strings.NewReader(body)))
	return w
}

// doRuleAction: rule edits go through the package's AdGuard (the fake set by useFake).
func doRuleAction(body string) *httptest.ResponseRecorder { return httptestFiltering(&Service{}, body) }

// The panel's client exception (marker + rule) and a rule written by hand in AdGuard.
var keptRules = []string{allowMarker + "wg-3", "@@||shop.example^$client='10.8.0.3'", "/ads[0-9]+\\.example/$important"}

// Adding and removing touch only that one line: the panel's pairs and hand-written rules stay,
// and adding twice doesn't duplicate.
func TestCustomRuleAddRemoveTouchesOneLine(t *testing.T) {
	f := &fakeAdGuard{rules: slices.Clone(keptRules)}
	useFake(t, f)
	for i := 0; i < 2; i++ {
		if w := doRuleAction(`{"action":"addRule","domain":"Ads.Example.com."}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"domain":"ads.example.com"`) {
			t.Fatalf("addRule: %d %s", w.Code, w.Body)
		}
	}
	if w := doRuleAction(`{"action":"addRule","domain":"shop.example","allow":true}`); w.Code != http.StatusOK {
		t.Fatalf("addRule allow: %d %s", w.Code, w.Body)
	}
	want := append(slices.Clone(keptRules), "||ads.example.com^", "@@||shop.example^")
	if !slices.Equal(f.rules, want) {
		t.Fatalf("after add:\n got %q\nwant %q", f.rules, want)
	}
	// removing the everyone-wide allow for shop.example leaves the client's exception alone
	if w := doRuleAction(`{"action":"removeRule","domain":"shop.example","allow":true}`); w.Code != http.StatusOK {
		t.Fatalf("removeRule: %d %s", w.Code, w.Body)
	}
	if w := doRuleAction(`{"action":"removeRule","domain":"ads.example.com"}`); w.Code != http.StatusOK {
		t.Fatalf("removeRule: %d %s", w.Code, w.Body)
	}
	if !slices.Equal(f.rules, keptRules) {
		t.Fatalf("after remove:\n got %q\nwant %q", f.rules, keptRules)
	}
}

// Anything that isn't a plain hostname is refused and the rules are never written.
func TestCustomRuleRejectsRuleSyntax(t *testing.T) {
	f := &fakeAdGuard{rules: slices.Clone(keptRules)}
	useFake(t, f)
	for _, d := range []string{"", "a.com^$important", "||a.com", "@@||a.com^", "a.com\n||b.com^", "*.a.com", "a com", "a.com/x", "a.com'", strings.Repeat("a", 250) + ".com"} {
		for _, action := range []string{"addRule", "removeRule"} {
			body := `{"action":"` + action + `","domain":` + jsonString(d) + `}`
			if w := doRuleAction(body); w.Code != http.StatusBadRequest {
				t.Errorf("%s %q: status %d, want 400", action, d, w.Code)
			}
		}
	}
	if !slices.Equal(f.rules, keptRules) {
		t.Fatalf("rules changed: %q", f.rules)
	}
}

// The old whole-list replace is gone.
func TestSetRulesRemoved(t *testing.T) {
	f := &fakeAdGuard{rules: slices.Clone(keptRules)}
	useFake(t, f)
	if w := doRuleAction(`{"action":"setRules","rules":[]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("setRules: status %d, want 400", w.Code)
	}
	if !slices.Equal(f.rules, keptRules) {
		t.Fatalf("rules changed: %q", f.rules)
	}
}

func jsonString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}
