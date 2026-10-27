package adguard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rewriteCall is one request the fake AdGuard received.
type rewriteCall struct {
	method, path string
	body         map[string]any
}

// rewriteService is a Service pointed at a fake AdGuard that records every call and answers
// with status (200 when 0).
func rewriteService(t *testing.T, status int) (*Service, *[]rewriteCall) {
	t.Helper()
	var calls []rewriteCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		calls = append(calls, rewriteCall{r.Method, r.URL.Path, body})
		if status != 0 {
			w.WriteHeader(status)
			io.WriteString(w, "target rule not found")
		}
	}))
	t.Cleanup(srv.Close)
	return &Service{adguardAPI: srv.URL}, &calls
}

func doRewrite(s *Service, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	s.handleRewriteAction(w, httptest.NewRequest("PUT", "/api/adguard/rewrites", strings.NewReader(body)))
	return w
}

func TestRewriteUpdateForwardsOneCall(t *testing.T) {
	s, calls := rewriteService(t, 0)
	w := doRewrite(s, `{"action":"update","target":{"domain":"nas.home","answer":"10.8.0.50","enabled":true},"domain":"nas.home","answer":"10.8.0.51","enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if len(*calls) != 1 {
		t.Fatalf("want one AdGuard call, got %d", len(*calls))
	}
	c := (*calls)[0]
	if c.method != "PUT" || c.path != "/control/rewrite/update" {
		t.Fatalf("call = %s %s", c.method, c.path)
	}
	// the target is matched by domain and answer only; the client's target.enabled isn't passed on
	target, update := c.body["target"].(map[string]any), c.body["update"].(map[string]any)
	if len(target) != 2 || target["domain"] != "nas.home" || target["answer"] != "10.8.0.50" {
		t.Fatalf("target = %v", target)
	}
	if update["domain"] != "nas.home" || update["answer"] != "10.8.0.51" || update["enabled"] != false {
		t.Fatalf("update = %v", update)
	}
}

// Nothing invalid reaches AdGuard: every bad update is refused before any call.
func TestRewriteUpdateRejectsBadInput(t *testing.T) {
	for name, body := range map[string]string{
		"no enabled":         `{"action":"update","target":{"domain":"a.home","answer":"10.0.0.1"},"domain":"a.home","answer":"10.0.0.2"}`,
		"no target":          `{"action":"update","domain":"a.home","answer":"10.0.0.2","enabled":true}`,
		"target no answer":   `{"action":"update","target":{"domain":"a.home"},"domain":"a.home","answer":"10.0.0.2","enabled":true}`,
		"no new answer":      `{"action":"update","target":{"domain":"a.home","answer":"10.0.0.1"},"domain":"a.home","enabled":true}`,
		"control char":       `{"action":"update","target":{"domain":"a.home","answer":"10.0.0.1"},"domain":"a.home\n||b.com^","answer":"10.0.0.2","enabled":true}`,
		"space in target":    `{"action":"update","target":{"domain":"a .home","answer":"10.0.0.1"},"domain":"a.home","answer":"10.0.0.2","enabled":true}`,
		"oversized":          `{"action":"update","target":{"domain":"a.home","answer":"10.0.0.1"},"domain":"` + strings.Repeat("a", 254) + `","answer":"10.0.0.2","enabled":true}`,
		"enabled not a bool": `{"action":"update","target":{"domain":"a.home","answer":"10.0.0.1"},"domain":"a.home","answer":"10.0.0.2","enabled":"yes"}`,
	} {
		s, calls := rewriteService(t, 0)
		if w := doRewrite(s, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, w.Code)
		}
		if len(*calls) != 0 {
			t.Errorf("%s: %d call(s) reached AdGuard", name, len(*calls))
		}
	}
}

// add and delete send exactly what they did before: domain and answer, no enabled field.
func TestRewriteAddDeleteUnchanged(t *testing.T) {
	for _, action := range []string{"add", "delete"} {
		s, calls := rewriteService(t, 0)
		if w := doRewrite(s, `{"action":"`+action+`","domain":"nas.home","answer":"10.8.0.50","enabled":false}`); w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", action, w.Code)
		}
		c := (*calls)[0]
		if c.method != "POST" || c.path != "/control/rewrite/"+action || len(c.body) != 2 || c.body["domain"] != "nas.home" || c.body["answer"] != "10.8.0.50" {
			t.Fatalf("%s: call = %s %s %v", action, c.method, c.path, c.body)
		}
		s, calls = rewriteService(t, 0)
		if w := doRewrite(s, `{"action":"`+action+`","domain":"nas.home"}`); w.Code != http.StatusBadRequest || len(*calls) != 0 {
			t.Fatalf("%s without answer: status %d, %d call(s)", action, w.Code, len(*calls))
		}
	}
}

func TestRewriteUnknownActionAndAdGuardRefusal(t *testing.T) {
	s, calls := rewriteService(t, 0)
	for _, body := range []string{`{"action":"drop"}`, `{}`} {
		if w := doRewrite(s, body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d", body, w.Code)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("%d call(s) reached AdGuard", len(*calls))
	}
	// AdGuard's own refusal (e.g. the target is gone) is passed back, never reported as success
	s, _ = rewriteService(t, http.StatusBadRequest)
	w := doRewrite(s, `{"action":"update","target":{"domain":"gone.home","answer":"10.0.0.1"},"domain":"gone.home","answer":"10.0.0.2","enabled":true}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "not found") {
		t.Fatalf("refusal: status %d %q", w.Code, w.Body)
	}
}
