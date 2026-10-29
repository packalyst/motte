package headscale

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/helper"
	"api/internal/router"
)

const syntheticJoinKey = "00000000000000000000000000000000synthetic"

// nodeJSON is a Headscale 0.25-shaped node carrying the key it joined with.
const nodeJSON = `{"id":"7","name":"laptop","ipAddresses":["100.64.0.7"],"online":true,` +
	`"preAuthKey":{"id":"18","key":"` + syntheticJoinKey + `","reusable":true,"used":true}}`

func TestStripJoinKeys(t *testing.T) {
	for name, body := range map[string]string{
		"node list":   `{"nodes":[` + nodeJSON + `]}`,
		"one node":    `{"node":` + nodeJSON + `}`,
		"route lists": `{"routes":[{"id":"3","prefix":"192.168.1.0/24","node":` + nodeJSON + `}]}`,
	} {
		out, err := StripJoinKeys([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(string(out), syntheticJoinKey) || strings.Contains(string(out), "preAuthKey") {
			t.Errorf("%s: join key left in %s", name, out)
		}
		if !strings.Contains(string(out), `"100.64.0.7"`) || !strings.Contains(string(out), `"online":true`) {
			t.Errorf("%s: node data lost: %s", name, out)
		}
	}
	if out, err := StripJoinKeys(nil); err != nil || len(out) != 0 {
		t.Errorf("empty body: %q, %v", out, err)
	}
	if _, err := StripJoinKeys([]byte("not json")); err == nil {
		t.Error("non-JSON body should be an error, never relayed as is")
	}
}

// TestProxyResponseJoinKeys: node replies reach the browser without join keys, the key list with
// only each key's prefix; a reply that can't be cleaned is not relayed.
func TestProxyResponseJoinKeys(t *testing.T) {
	relay := func(path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		resp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
		(&Service{}).proxyResponse(rec, resp, path)
		return rec
	}
	if rec := relay("/node", `{"nodes":[`+nodeJSON+`]}`); strings.Contains(rec.Body.String(), syntheticJoinKey) || rec.Code != http.StatusOK {
		t.Errorf("node list: %d %s", rec.Code, rec.Body)
	}
	list := `{"preAuthKeys":[{"id":"20","key":"` + syntheticJoinKey + `","used":false}]}`
	if rec := relay("/preauthkey?user=alice", list); strings.Contains(rec.Body.String(), syntheticJoinKey) ||
		!strings.Contains(rec.Body.String(), `"keyPrefix":"`+syntheticJoinKey[:keyPrefixLen]+`"`) || !strings.Contains(rec.Body.String(), `"id":"20"`) {
		t.Errorf("key list must carry only each key's prefix: %s", rec.Body)
	}
	if rec := relay("/node", "not json "+syntheticJoinKey); rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), syntheticJoinKey) {
		t.Errorf("unreadable reply: %d %s, want 502 without the body", rec.Code, rec.Body)
	}
}

// fakeHeadscale serves a pre-auth key list for alice (key id 20) and records what's posted.
func fakeHeadscale(t *testing.T) *[]string {
	t.Helper()
	posted := &[]string{}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/preauthkey"):
			w.Write([]byte(`{"preAuthKeys":[{"id":"20","key":"` + syntheticJoinKey + `","used":false}]}`))
		case r.Method == http.MethodPost:
			b, _ := io.ReadAll(r.Body)
			*posted = append(*posted, r.URL.Path+" "+string(b))
			if strings.HasSuffix(r.URL.Path, "/expire") {
				w.Write([]byte(`{}`))
				return
			}
			w.Write([]byte(`{"preAuthKey":{"id":"21","key":"` + syntheticJoinKey + `new"}}`))
		}
	}))
	t.Cleanup(hs.Close)
	helper.SetHeadscaleConfigProvider(func() (*helper.HeadscaleConfig, error) {
		return &helper.HeadscaleConfig{URL: hs.URL, APIKey: "synthetic"}, nil
	})
	t.Cleanup(func() { helper.SetHeadscaleConfigProvider(nil) })
	return posted
}

// Show once: a new key comes back whole; the list shows prefixes; a key is expired by its id, the
// panel looking up the whole key itself.
func TestPreAuthKeysShownOnce(t *testing.T) {
	posted := fakeHeadscale(t)
	s := &Service{}
	call := func(h http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
		return rec
	}

	if rec := call(s.handleGetPreAuthKeys, http.MethodGet, "/api/hs/preauthkeys?user=alice", ""); strings.Contains(rec.Body.String(), syntheticJoinKey) {
		t.Errorf("list carries a whole key: %s", rec.Body)
	}

	router.SetStepUpFunc(func(http.ResponseWriter, *http.Request) bool { return true })
	t.Cleanup(func() { router.SetStepUpFunc(nil) })
	if rec := call(s.handleCreatePreAuthKey, http.MethodPost, "/api/hs/preauthkeys", `{"user":"alice"}`); !strings.Contains(rec.Body.String(), syntheticJoinKey+"new") {
		t.Errorf("a new key must be shown once: %s", rec.Body)
	}

	if rec := call(s.handleExpirePreAuthKey, http.MethodPost, "/api/hs/preauthkeys/expire", `{"user":"alice","id":"20"}`); rec.Code != http.StatusOK {
		t.Fatalf("expire: %d %s", rec.Code, rec.Body)
	}
	last := (*posted)[len(*posted)-1]
	if !strings.HasSuffix(strings.Fields(last)[0], "/preauthkey/expire") || !strings.Contains(last, `"key":"`+syntheticJoinKey+`"`) {
		t.Fatalf("expire sent %q", last)
	}

	n := len(*posted)
	for body, want := range map[string]int{
		`{"user":"alice","id":"99"}`:   http.StatusNotFound,
		`{"user":"alice","id":"20&x"}`: http.StatusBadRequest,
		`{"user":"a/b","id":"20"}`:     http.StatusBadRequest,
	} {
		if rec := call(s.handleExpirePreAuthKey, http.MethodPost, "/api/hs/preauthkeys/expire", body); rec.Code != want {
			t.Errorf("%s: %d, want %d", body, rec.Code, want)
		}
	}
	if len(*posted) != n {
		t.Fatal("an invalid or unknown expire reached Headscale")
	}
}
