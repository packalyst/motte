package fleet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// withTestSigningKey bakes a fresh signing key into the panel for the test and returns a
// signer for checksums.txt.
func withTestSigningKey(t *testing.T) func([]byte) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	orig := signPubKey
	signPubKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { signPubKey = orig })
	return func(b []byte) string { return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)) }
}

// releaseCache builds a cache over a fake, correctly signed release whose checksums.txt lists
// `listed`, while the server returns `served` for each asset — so a test can serve a tampered
// file.
func releaseCache(t *testing.T, listed, served map[string]string) *agentCache {
	t.Helper()
	sign := withTestSigningKey(t)
	var sums strings.Builder
	for name, body := range listed {
		h := sha256.Sum256([]byte(body))
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), name)
	}
	sig := sign([]byte(sums.String()))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		switch name {
		case "checksums.txt":
			fmt.Fprint(w, sums.String())
			return
		case "checksums.txt.sig":
			fmt.Fprint(w, sig)
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
	"motte-agent-linux-amd64": "binary",
	"manifest.json":           `{"tools":{}}`,
	"install.sh":              "#!/bin/sh\necho install\n",
}

// Every asset the installer hands out, not only the binary, must match the signed checksums.
func TestAgentCacheServesVerifiedAssets(t *testing.T) {
	c := releaseCache(t, release, release)
	bin, manifest, installSh, err := c.Get(context.Background(), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if string(bin) != release["motte-agent-linux-amd64"] || string(manifest) != release["manifest.json"] || string(installSh) != release["install.sh"] {
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
	listed := map[string]string{"motte-agent-linux-amd64": release["motte-agent-linux-amd64"]}
	c := releaseCache(t, listed, release)
	if _, _, _, err := c.Get(context.Background(), "amd64"); err == nil || !strings.Contains(err.Error(), "no checksum") {
		t.Fatalf("want no-checksum error, got %v", err)
	}
}

// countingForge reports how often the latest release was asked for.
type countingForge struct {
	testForge
	n *int
}

func (f countingForge) LatestTag(context.Context, *http.Client) (string, error) {
	*f.n++
	return "agent-v0.1.55", nil
}

// "Check for updates" skips the 30-minute cache, but asks the forge at most once a minute.
func TestRecheckLatestVersionRateLimited(t *testing.T) {
	n := 0
	c := &agentCache{forge: countingForge{n: &n}, http: http.DefaultClient}
	if v := c.LatestVersion(context.Background()); v != "0.1.55" || n != 1 {
		t.Fatalf("first lookup: %q after %d calls", v, n)
	}
	c.RecheckLatestVersion(context.Background())
	c.RecheckLatestVersion(context.Background())
	if n != 1 {
		t.Fatalf("rechecks within a minute asked the forge %d times", n)
	}
	c.versionAt = time.Now().Add(-2 * time.Minute)
	if v := c.RecheckLatestVersion(context.Background()); v != "0.1.55" || n != 2 {
		t.Fatalf("recheck after a minute: %q after %d calls", v, n)
	}
}

// A panel built without the signing key serves no agent release at all (installs and updates
// stop) instead of trusting unsigned binaries.
func TestAgentCacheRefusesWithoutSigningKey(t *testing.T) {
	c := releaseCache(t, release, release)
	signPubKey = "" // restored by the cleanup releaseCache registered
	if _, _, _, err := c.Get(context.Background(), "amd64"); err == nil || !strings.Contains(err.Error(), "without the release signing key") {
		t.Fatalf("want refusal without a signing key, got %v", err)
	}
}

// A release whose signature doesn't verify is never served.
func TestAgentCacheRejectsBadSignature(t *testing.T) {
	c := releaseCache(t, release, release)
	withTestSigningKey(t) // the panel now trusts a different key than the release was signed with
	if _, _, _, err := c.Get(context.Background(), "amd64"); err == nil || !strings.Contains(err.Error(), "reject release") {
		t.Fatalf("want signature rejection, got %v", err)
	}
}

// The cache never steps back: when the forge's "latest" is older than the cached release, new
// installs keep the cached one; a newer one is taken.
func TestAgentCacheNeverDowngrades(t *testing.T) {
	c := releaseCache(t, release, release) // the forge says latest is agent-v0.0.1
	c.tag, c.checksums = "agent-v0.1.55", "cached"
	if v, _, _, err := c.LatestSigned(context.Background()); err != nil || v != "0.1.55" {
		t.Fatalf("older latest: serving %q (%v), want the cached 0.1.55", v, err)
	}

	c2 := releaseCache(t, release, release)
	c2.tag, c2.checksums = "agent-v0.0.0", "cached"
	if v, _, _, err := c2.LatestSigned(context.Background()); err != nil || v != "0.0.1" {
		t.Fatalf("newer latest: serving %q (%v), want 0.0.1", v, err)
	}
}

func TestReleaseAtLeast(t *testing.T) {
	for _, c := range []struct {
		tag, current string
		want         bool
	}{
		{"agent-v0.1.56", "agent-v0.1.55", true},
		{"agent-v0.1.55", "agent-v0.1.55", true},
		{"agent-v0.1.9", "agent-v0.1.10", false},
		{"v1.0", "agent-v0.9.9", true},
		{"agent-v0.2.0-rc1", "agent-v0.1.99", true},
		{"agent-vnext", "agent-v0.1.0", false},
		{"agent-v0.0.1", "weird-tag", true},
	} {
		if got := releaseAtLeast(c.tag, c.current); got != c.want {
			t.Errorf("releaseAtLeast(%q, %q) = %v, want %v", c.tag, c.current, got, c.want)
		}
	}
}
