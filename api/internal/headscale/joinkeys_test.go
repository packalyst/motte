package headscale

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

// TestProxyResponseJoinKeys: node replies reach the browser without join keys; the pre-auth key
// endpoints still return theirs; a reply that can't be cleaned is not relayed.
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
	created := `{"preAuthKey":{"id":"19","key":"` + syntheticJoinKey + `"}}`
	if rec := relay("/preauthkey", created); !strings.Contains(rec.Body.String(), syntheticJoinKey) {
		t.Errorf("pre-auth key reply lost its key: %s", rec.Body)
	}
	if rec := relay("/node", "not json "+syntheticJoinKey); rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), syntheticJoinKey) {
		t.Errorf("unreadable reply: %d %s, want 502 without the body", rec.Code, rec.Body)
	}
}
