package fleet

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"api/internal/helper"
)

// agentCache serves the wgscout agent assets (binary + manifest + install.sh) by pulling
// them LIVE from the GitHub release and caching them on the panel's disk — so the repo
// carries no binaries and a new agent ships with a plain `gh release`, no panel rebuild.
//
// Freshness without the GitHub API: the release's tiny checksums.txt is the version
// marker. At most every `ttl`, we re-fetch checksums.txt; if it changed, a new release is
// out, so we purge the cache and lazily re-fetch. Binaries are verified against it before
// they're ever served (fail-closed).
type agentCache struct {
	dir   string // on-disk cache dir
	forge Forge  // release-asset URL scheme for the configured host (nil = serving disabled)
	http  *http.Client
	ttl   time.Duration

	mu        sync.Mutex
	tag       string    // release tag the cached assets belong to (resolved from the forge)
	checksums string    // cached checksums.txt content (the version marker)
	sig       string    // base64 ed25519 signature over checksums (empty if signing is off)
	lastCheck time.Time // when we last re-validated against the release

	// Latest agent version (release tag_name, e.g. "0.1.21"), resolved from the
	// GitHub API and cached — so the UI can show "update available" without hitting
	// the API on every request.
	version   string
	versionAt time.Time
}

func newAgentCache() *agentCache {
	// The repo identity comes entirely from the environment (SOURCE_REPO full URL +
	// SOURCE_FORGE), derived from the git remote by manage.sh and defaulted in
	// docker-compose — nothing is baked into the binary. A missing or invalid config
	// leaves forge nil, and asset serving / version checks fail gracefully (best-effort).
	var forge Forge
	repo := helper.GetEnvOptional("SOURCE_REPO", "")
	if repo == "" {
		log.Print("fleet: SOURCE_REPO is not set; agent asset serving and version checks are disabled")
	} else if f, err := newForge(repo, helper.GetEnvOptional("SOURCE_FORGE", "")); err != nil {
		log.Printf("fleet: invalid SOURCE_REPO/SOURCE_FORGE (%v); agent asset serving and version checks are disabled", err)
	} else {
		forge = f
	}
	return &agentCache{
		dir:   helper.GetEnvOptional("FLEET_AGENT_CACHE", "/data/fleet-agent"),
		forge: forge,
		http:  &http.Client{Timeout: 90 * time.Second},
		ttl:   5 * time.Minute,
	}
}

// LatestVersion returns the newest published agent version (release tag_name minus the
// "agent-v" prefix, e.g. "0.1.21"), resolved from the GitHub API and cached for 30
// minutes. Best-effort: on any failure it returns the last known value (or "" if never
// resolved), so the UI degrades to just showing the running version.
func (c *agentCache) LatestVersion(ctx context.Context) string {
	c.mu.Lock()
	last := c.version
	if c.forge == nil || (c.version != "" && time.Since(c.versionAt) < 30*time.Minute) {
		c.mu.Unlock()
		return last
	}
	forge := c.forge
	c.mu.Unlock()

	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tag, err := forge.LatestTag(cctx, c.http)
	if err != nil {
		return last // keep last known
	}
	v := strings.TrimPrefix(strings.TrimPrefix(tag, "agent-v"), "v")
	if v == "" {
		return last
	}
	c.mu.Lock()
	c.version, c.versionAt = v, time.Now()
	c.mu.Unlock()
	return v
}

// Get returns the cached (binary, manifest, install.sh) for arch, fetching+verifying from
// the latest release on a cold cache or after a new release. Caller holds no lock.
func (c *agentCache) Get(ctx context.Context, arch string) (bin, manifest, installSh []byte, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.refreshLocked(ctx); err != nil {
		return nil, nil, nil, err
	}
	binName := "wgscout-linux-" + arch
	bin, err = c.ensureVerifiedLocked(ctx, binName)
	if err != nil {
		return nil, nil, nil, err
	}
	if manifest, err = c.ensureLocked(ctx, "manifest.json"); err != nil {
		return nil, nil, nil, err
	}
	if installSh, err = c.ensureLocked(ctx, "install.sh"); err != nil {
		return nil, nil, nil, err
	}
	return bin, manifest, installSh, nil
}

// LatestSigned refreshes and returns the latest release's agent version (tag minus the
// "agent-v"/"v" prefix), the raw checksums.txt content, and the base64 ed25519 signature
// over it (empty when signing is disabled). The agent uses this to decide whether to update
// and to verify the download itself before trusting it.
func (c *agentCache) LatestSigned(ctx context.Context) (version, checksums, sig string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err = c.refreshLocked(ctx); err != nil {
		return "", "", "", err
	}
	version = strings.TrimPrefix(strings.TrimPrefix(c.tag, "agent-v"), "v")
	return version, c.checksums, c.sig, nil
}

// Binary refreshes and returns the checksum-verified agent binary for arch (e.g. "amd64").
func (c *agentCache) Binary(ctx context.Context, arch string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.refreshLocked(ctx); err != nil {
		return nil, err
	}
	return c.ensureVerifiedLocked(ctx, "wgscout-linux-"+arch)
}

// refreshLocked re-validates the cache against the release at most once per ttl. It resolves
// the latest release tag from the forge, then fetches that tag's checksums.txt; if the tag or
// checksums changed (new version) it wipes the cache so assets re-download under the new tag.
func (c *agentCache) refreshLocked(ctx context.Context) error {
	if c.forge == nil {
		return fmt.Errorf("agent asset serving is disabled: SOURCE_REPO/SOURCE_FORGE not configured")
	}
	if c.checksums == "" {
		// cold start — reload the cached checksums.txt and the tag it belongs to from disk.
		if b, e := os.ReadFile(filepath.Join(c.dir, "checksums.txt")); e == nil {
			c.checksums = string(b)
		}
		if b, e := os.ReadFile(filepath.Join(c.dir, ".tag")); e == nil {
			if t := strings.TrimSpace(string(b)); reTag.MatchString(t) {
				c.tag = t
			}
		}
		if b, e := os.ReadFile(filepath.Join(c.dir, "checksums.txt.sig")); e == nil {
			c.sig = strings.TrimSpace(string(b))
		}
	} else if time.Since(c.lastCheck) < c.ttl {
		return nil // still fresh
	}

	tag, err := c.forge.LatestTag(ctx, c.http)
	if err != nil {
		if c.checksums != "" && c.tag != "" {
			return nil // forge unreachable but we have a cached release — serve it
		}
		return fmt.Errorf("resolve latest release: %w", err)
	}
	latest, err := c.fetchAsset(ctx, tag, "checksums.txt")
	if err != nil {
		if c.checksums != "" && c.tag != "" {
			return nil // release unreachable but we have a cached version — serve it
		}
		return fmt.Errorf("fetch checksums: %w", err)
	}
	// We reached the forge — record the check time now, before verifying, so a subsequent
	// signature failure still throttles the next attempt (otherwise every request after a
	// bad/failed verify would re-hit the forge with no backoff).
	c.lastCheck = time.Now()
	// When the panel is built with a signing key, the release's checksums.txt MUST carry a
	// valid ed25519 signature before we trust it. Fail-closed: a missing or bad signature is
	// never served, and we keep any previously-verified cache rather than accepting it.
	var sigStr string
	if signingEnabled() {
		sig, serr := c.fetchAsset(ctx, tag, "checksums.txt.sig")
		if serr != nil {
			if c.checksums != "" && c.tag != "" {
				return nil // signature unreachable — keep serving the last verified release
			}
			return fmt.Errorf("fetch release signature: %w", serr)
		}
		if verr := verifyChecksumsSig(latest, sig); verr != nil {
			return fmt.Errorf("reject release %s: %w", tag, verr)
		}
		sigStr = strings.TrimSpace(string(sig))
	}
	if tag == c.tag && string(latest) == c.checksums {
		c.sig = sigStr // keep the signature fresh even when the release is unchanged
		return nil
	}
	// New release (or first run): drop the whole cache and re-seed the marker + tag + sig.
	if err := os.RemoveAll(c.dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("purge cache: %w", err)
	}
	if err := os.MkdirAll(c.dir, 0o750); err != nil {
		return err
	}
	c.checksums, c.tag, c.sig = string(latest), tag, sigStr
	if err := writeFileAtomic(filepath.Join(c.dir, ".tag"), []byte(tag)); err != nil {
		return err
	}
	if sigStr != "" {
		if err := writeFileAtomic(filepath.Join(c.dir, "checksums.txt.sig"), []byte(sigStr)); err != nil {
			return err
		}
	}
	return writeFileAtomic(filepath.Join(c.dir, "checksums.txt"), latest)
}

// ensureLocked returns a cached asset, fetching it if absent (no checksum — matched to the
// current version by living under the same purged-on-change cache dir).
func (c *agentCache) ensureLocked(ctx context.Context, name string) ([]byte, error) {
	path := filepath.Join(c.dir, name)
	if b, err := os.ReadFile(path); err == nil {
		return b, nil
	}
	b, err := c.fetch(ctx, name)
	if err != nil {
		return nil, err
	}
	return b, writeFileAtomic(path, b)
}

// ensureVerifiedLocked returns a cached binary, fetching + checksum-verifying it if absent.
// A binary whose sha256 doesn't match the release's checksums.txt is never written/served.
func (c *agentCache) ensureVerifiedLocked(ctx context.Context, name string) ([]byte, error) {
	path := filepath.Join(c.dir, name)
	if b, err := os.ReadFile(path); err == nil {
		return b, nil // already verified when it was written
	}
	want, ok := checksumFor(c.checksums, name)
	if !ok {
		return nil, fmt.Errorf("no checksum for %q in release", name)
	}
	b, err := c.fetch(ctx, name)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("%s checksum mismatch (want %s got %s)", name, want, got)
	}
	return b, writeFileAtomic(path, b)
}

// fetch downloads a named asset for the currently-resolved tag.
func (c *agentCache) fetch(ctx context.Context, name string) ([]byte, error) {
	return c.fetchAsset(ctx, c.tag, name)
}

// fetchAsset downloads a named release asset at tag from the forge over https, size-capped.
// The asset name is allowlist-validated so it can never manipulate the URL path.
func (c *agentCache) fetchAsset(ctx context.Context, tag, name string) ([]byte, error) {
	if c.forge == nil {
		return nil, fmt.Errorf("forge not configured")
	}
	if !reSegment.MatchString(name) {
		return nil, fmt.Errorf("invalid asset name %q", name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.forge.AssetURL(tag, name), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", name, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MiB cap
}

// checksumFor parses `sha256␠␠filename` lines (sha256sum format) and returns the hash for
// name.
func checksumFor(checksums, name string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(checksums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && fields[1] == name {
			return fields[0], true
		}
	}
	return "", false
}

// writeFileAtomic writes via a temp file + rename so a concurrent reader never sees a
// half-written asset.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
