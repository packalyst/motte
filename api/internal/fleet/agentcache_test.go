package fleet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testForge serves release assets from an httptest server.
type testForge struct{ base string }

func (f testForge) AssetURL(tag, asset string) string { return f.base + "/" + tag + "/" + asset }
func (f testForge) LatestTag(context.Context, *http.Client) (string, error) {
	return "agent-v0.0.1", nil
}

// releaseCache builds a cache over a fake release whose checksums.txt lists `listed`, while
// the server returns `served` for each asset — so a test can serve a tampered file.
func releaseCache(t *testing.T, listed, served map[string]string) *agentCache {
	t.Helper()
	var sums strings.Builder
	for name, body := range listed {
		h := sha256.Sum256([]byte(body))
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), name)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if name == "checksums.txt" {
			fmt.Fprint(w, sums.String())
			return
		}
		body, ok := served[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return &agentCache{dir: t.TempDir(), forge: testForge{srv.URL}, http: srv.Client(), ttl: time.Minute}
}

var release = map[string]string{
	"wgscout-linux-amd64": "binary",
	"manifest.json":       `{"tools":{}}`,
	"install.sh":          "#!/bin/sh\necho install\n",
}

// Every asset the installer hands out, not only the binary, must match the signed checksums.
func TestAgentCacheServesVerifiedAssets(t *testing.T) {
	c := releaseCache(t, release, release)
	bin, manifest, installSh, err := c.Get(context.Background(), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if string(bin) != release["wgscout-linux-amd64"] || string(manifest) != release["manifest.json"] || string(installSh) != release["install.sh"] {
		t.Fatal("served assets differ from the release")
	}
}

// A swapped install.sh (run as root) or manifest.json (pins root-installed tools) is refused.
func TestAgentCacheRejectsTamperedAssets(t *testing.T) {
	for _, name := range []string{"install.sh", "manifest.json"} {
		served := map[string]string{}
		for k, v := range release {
			served[k] = v
		}
		served[name] = "tampered"
		c := releaseCache(t, release, served)
		if _, _, _, err := c.Get(context.Background(), "amd64"); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
			t.Errorf("%s: want checksum mismatch, got %v", name, err)
		}
	}
}

// An asset missing from checksums.txt (an old-style release) is never served unverified.
func TestAgentCacheRejectsUnlistedAssets(t *testing.T) {
	listed := map[string]string{"wgscout-linux-amd64": release["wgscout-linux-amd64"]}
	c := releaseCache(t, listed, release)
	if _, _, _, err := c.Get(context.Background(), "amd64"); err == nil || !strings.Contains(err.Error(), "no checksum") {
		t.Fatalf("want no-checksum error, got %v", err)
	}
}
