package vpn

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/helper"
)

// TestStoredNodesHaveNoJoinKey: node data fetched for the client list (stored, and shown to
// viewers as rawData) carries no join key.
func TestStoredNodesHaveNoJoinKey(t *testing.T) {
	const key = "00000000000000000000000000000000synthetic"
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"nodes":[{"id":"7","name":"laptop","ipAddresses":["100.64.0.7"],` +
			`"preAuthKey":{"id":"18","key":"` + key + `","reusable":true}}]}`))
	}))
	defer hs.Close()
	helper.SetHeadscaleConfigProvider(func() (*helper.HeadscaleConfig, error) {
		return &helper.HeadscaleConfig{URL: hs.URL, APIKey: "synthetic"}, nil
	})
	t.Cleanup(func() { helper.SetHeadscaleConfigProvider(nil) })

	nodes, raw, err := (&Service{}).getHeadscaleNodesWithRaw()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].IP != "100.64.0.7" || len(raw) != 1 {
		t.Fatalf("got nodes %+v raw %d", nodes, len(raw))
	}
	if strings.Contains(raw[0], key) || strings.Contains(raw[0], "preAuthKey") {
		t.Errorf("stored node data keeps the join key: %s", raw[0])
	}
}
