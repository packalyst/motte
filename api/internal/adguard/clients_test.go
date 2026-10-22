package adguard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeAdGuard is the slice of the AdGuard API the per-client code uses, with in-memory state.
type fakeAdGuard struct {
	mu      sync.Mutex
	clients []map[string]any
	rules   []string
	log     []map[string]any
}

func useFake(t *testing.T, f *fakeAdGuard) {
	t.Helper()
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any) { json.NewEncoder(w).Encode(v) }
	read := func(r *http.Request) map[string]any {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		return m
	}
	mux.HandleFunc("/control/clients", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		reply(w, map[string]any{"clients": f.clients})
	})
	mux.HandleFunc("/control/clients/add", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.clients = append(f.clients, read(r))
	})
	mux.HandleFunc("/control/clients/update", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		m := read(r)
		for i, c := range f.clients {
			if c["name"] == m["name"] {
				f.clients[i] = m["data"].(map[string]any)
			}
		}
	})
	mux.HandleFunc("/control/clients/delete", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		m := read(r)
		out := f.clients[:0]
		for _, c := range f.clients {
			if c["name"] != m["name"] {
				out = append(out, c)
			}
		}
		f.clients = out
	})
	mux.HandleFunc("/control/filtering/status", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		reply(w, map[string]any{"enabled": true, "user_rules": f.rules})
	})
	mux.HandleFunc("/control/filtering/set_rules", func(w http.ResponseWriter, r *http.Request) {
		var m struct{ Rules []string }
		json.NewDecoder(r.Body).Decode(&m)
		f.mu.Lock()
		f.rules = m.Rules
		f.mu.Unlock()
	})
	mux.HandleFunc("/control/safebrowsing/status", func(w http.ResponseWriter, r *http.Request) { reply(w, map[string]any{"enabled": true}) })
	mux.HandleFunc("/control/parental/status", func(w http.ResponseWriter, r *http.Request) { reply(w, map[string]any{"enabled": false}) })
	mux.HandleFunc("/control/safesearch/status", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"enabled": true, "google": true})
	})
	mux.HandleFunc("/control/querylog", func(w http.ResponseWriter, r *http.Request) { reply(w, map[string]any{"data": f.log}) })
	srv := httptest.NewServer(mux)
	prev := serviceInstance
	serviceInstance = &Service{adguardAPI: srv.URL}
	t.Cleanup(func() { srv.Close(); serviceInstance = prev })
}

// Anything that could carry rule syntax into AdGuard is rejected.
func TestNormalizeDomain(t *testing.T) {
	for _, bad := range []string{"", "a.com^$important", "a.com'", "a b.com", "@@||a.com", "a.com\n||b.com^",
		"-a.com", "a-.com", "*.a.com", "a..com", "a.com/x", "ex%61mple.com", "exämple.com", strings.Repeat("a", 254)} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	if d, err := NormalizeDomain(" Ads.Example.COM. "); err != nil || d != "ads.example.com" {
		t.Errorf("want ads.example.com, got %q (%v)", d, err)
	}
}

func TestValidKey(t *testing.T) {
	for _, bad := range []string{"", "m:abc", "wg:", "wg:1\n! x", "wg:1'", "lan:1 2", "WG:1"} {
		if ValidKey(bad) {
			t.Errorf("%q must be rejected", bad)
		}
	}
	for _, good := range []string{"wg:3", "ts:12", "lan:7"} {
		if !ValidKey(good) {
			t.Errorf("%q must be accepted", good)
		}
	}
}

// Turning blocking off adds the panel's own entry with filtering off and the other protections
// copied; turning it back on removes it. An address covered by an AdGuard entry the panel didn't
// make is refused and that entry is untouched.
func TestSetClientBlocking(t *testing.T) {
	f := &fakeAdGuard{clients: []map[string]any{{"name": "kids tablet", "ids": []any{"10.8.0.9"}}}}
	useFake(t, f)

	if err := SetClientBlocking("wg:3", "10.8.0.5", false); err != nil {
		t.Fatal(err)
	}
	if len(f.clients) != 2 || f.clients[1]["name"] != "wgpanel wg:3" || f.clients[1]["filtering_enabled"] != false ||
		f.clients[1]["safebrowsing_enabled"] != true || f.clients[1]["use_global_settings"] != false {
		t.Fatalf("unexpected entry: %+v", f.clients)
	}
	if !BlockingOff("wg:3") {
		t.Error("cache not updated")
	}
	st, err := ClientBlocking("wg:3", "10.8.0.5")
	if err != nil || st.Blocking {
		t.Fatalf("want blocking off, got %+v (%v)", st, err)
	}

	if err := SetClientBlocking("wg:3", "10.8.0.5", true); err != nil {
		t.Fatal(err)
	}
	if len(f.clients) != 1 || BlockingOff("wg:3") {
		t.Fatalf("entry not removed: %+v", f.clients)
	}

	if err := SetClientBlocking("wg:4", "10.8.0.9", false); err != ErrManagedElsewhere {
		t.Fatalf("want ErrManagedElsewhere, got %v", err)
	}
	if len(f.clients) != 1 || f.clients[0]["name"] != "kids tablet" {
		t.Fatal("a client entry the panel didn't make was changed")
	}
	if st, _ := ClientBlocking("wg:4", "10.8.0.9"); st.ManagedElsewhere != "kids tablet" {
		t.Errorf("want managed elsewhere, got %+v", st)
	}
}

// Allow rules are written under a marker; only marked rules are listed or removed.
func TestAllowRulesOnlyTouchPanelRules(t *testing.T) {
	hand := "@@||ads.example.com^$client='10.8.0.5'" // same format, written by hand: not ours
	f := &fakeAdGuard{rules: []string{"||tracker.example^", hand}}
	useFake(t, f)

	if err := SetAllowed("wg:3", "10.8.0.5", "ads.example.com", true); err != nil {
		t.Fatal(err)
	}
	if err := SetAllowed("wg:3", "10.8.0.5", "ads.example.com", true); err != nil { // idempotent
		t.Fatal(err)
	}
	if got, _ := AllowedForClient("wg:3", "10.8.0.5"); len(got) != 1 || got[0] != "ads.example.com" {
		t.Fatalf("want one allowed domain, got %v", got)
	}
	if len(f.rules) != 4 {
		t.Fatalf("want 2 existing + marker + rule, got %v", f.rules)
	}
	if err := SetAllowed("wg:3", "10.8.0.5", "ads.example.com", false); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.rules, "\n") != "||tracker.example^\n"+hand {
		t.Fatalf("removal touched other rules: %v", f.rules)
	}
	if err := SetAllowed("wg:3", "10.8.0.5", "a.com^$important", true); err == nil {
		t.Fatal("a domain with rule syntax must be rejected")
	}
}

// The sync removes the panel's entries and rules for clients that are gone, moves an entry to a
// client's new address (dropping rules for the old one), and leaves everything else alone.
func TestSyncManaged(t *testing.T) {
	f := &fakeAdGuard{
		clients: []map[string]any{
			{"name": "wgpanel wg:1", "ids": []any{"10.8.0.1"}},      // gone
			{"name": "wgpanel lan:2", "ids": []any{"192.168.50.5"}}, // moved to .6
			{"name": "wgpanel ts:3", "ids": []any{"100.64.0.3"}},    // unchanged
			{"name": "printer", "ids": []any{"192.168.50.9"}},       // not ours
		},
		rules: []string{
			allowMarker + "wg:1", allowRule("a.example.com", "10.8.0.1"),
			allowMarker + "lan:2", allowRule("b.example.com", "192.168.50.5"),
			allowMarker + "ts:3", allowRule("c.example.com", "100.64.0.3"),
			allowRule("d.example.com", "10.8.0.1"), // handwritten, same address as a gone client
		},
	}
	useFake(t, f)
	if err := SyncManaged(map[string]string{"lan:2": "192.168.50.6", "ts:3": "100.64.0.3"}); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, c := range f.clients {
		names = append(names, c["name"].(string))
		if c["name"] == "wgpanel lan:2" && c["ids"].([]any)[0] != "192.168.50.6" {
			t.Errorf("moved client not updated: %+v", c)
		}
	}
	if strings.Join(names, ",") != "wgpanel lan:2,wgpanel ts:3,printer" {
		t.Errorf("unexpected entries after sync: %v", names)
	}
	want := []string{allowMarker + "ts:3", allowRule("c.example.com", "100.64.0.3"), allowRule("d.example.com", "10.8.0.1")}
	if strings.Join(f.rules, "\n") != strings.Join(want, "\n") {
		t.Errorf("rules after sync:\n%v\nwant:\n%v", f.rules, want)
	}
}

// The query log search is a substring match; only the client's own exact address is kept.
func TestRecentBlockedExactClient(t *testing.T) {
	q := func(client, domain string) map[string]any {
		return map[string]any{"client": client, "question": map[string]any{"name": domain}, "reason": "FilteredBlackList"}
	}
	f := &fakeAdGuard{log: []map[string]any{q("10.8.0.50", "other.example"), q("10.8.0.5", "ads.example"), q("10.8.0.5", "ads.example")}}
	useFake(t, f)
	got, err := RecentBlocked("10.8.0.5", 20)
	if err != nil || len(got) != 1 || got[0].Domain != "ads.example" {
		t.Fatalf("want only the exact client's one domain, got %+v (%v)", got, err)
	}
}
