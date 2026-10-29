package sentinel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The visitor named in CF-Connecting-IP is trusted only when the peer is on the panel's
// Cloudflare list; with no list (none configured, or not fetched yet) the peer is the client.
func TestClientIPUsesPanelCloudflareList(t *testing.T) {
	ls := newListServer(t, "198.51.100.0/24\n2001:db8:cf::/48\n")
	mk := func(url string) *Sentinel {
		cfg := CreateConfig()
		cfg.CloudflareListURL = url
		h, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "t")
		if err != nil {
			t.Fatal(err)
		}
		return h.(*Sentinel)
	}
	req := func(remote string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("CF-Connecting-IP", "203.0.113.77")
		return r
	}
	s := mk(ls.srv.URL)
	for remote, want := range map[string]string{
		"198.51.100.4:443":       "203.0.113.77", // a listed edge: the header names the visitor
		"[2001:db8:cf::9]:443":   "203.0.113.77",
		"192.0.2.9:443":          "192.0.2.9", // anyone else: the header is ignored
		"[2001:db8:ffff::1]:443": "2001:db8:ffff::1",
	} {
		if got := s.getClientIP(req(remote)).String(); got != want {
			t.Errorf("%s: %s, want %s", remote, got, want)
		}
	}

	// An answer with no valid entry keeps the last good list.
	ls.set(http.StatusOK, "<html>oops</html>")
	expire(s.cfCache)
	if got := s.getClientIP(req("198.51.100.4:443")).String(); got != "203.0.113.77" {
		t.Errorf("an invalid answer dropped the list: %s", got)
	}

	// No list configured, or never fetched: no peer is trusted.
	for _, u := range []string{"", "http://127.0.0.1:1/unreachable"} {
		if got := mk(u).getClientIP(req("198.51.100.4:443")).String(); got != "198.51.100.4" {
			t.Errorf("list %q: %s, want the peer", u, got)
		}
	}
}
