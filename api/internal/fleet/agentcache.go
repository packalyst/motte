package fleet

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	dir     string // on-disk cache dir
	repo    string // <owner>/<repo> on GitHub
	baseURL string // https://github.com/<repo>/releases/latest/download
	http    *http.Client
	ttl     time.Duration

	mu        sync.Mutex
	checksums string    // cached checksums.txt content (the version marker)
	lastCheck time.Time // when we last re-validated against the release

	// Latest agent version (release tag_name, e.g. "0.1.21"), resolved from the
	// GitHub API and cached — so the UI can show "update available" without hitting
	// the API on every request.
	version   string
	versionAt time.Time
}

const agentRepoDefault = "packalyst/wireguard-admin-panel"

func newAgentCache() *agentCache {
	repo := helper.GetEnvOptional("FLEET_AGENT_REPO", agentRepoDefault)
	return &agentCache{
		dir:     helper.GetEnvOptional("FLEET_AGENT_CACHE", "/data/fleet-agent"),
		repo:    repo,
		baseURL: fmt.Sprintf("https://github.com/%s/releases/latest/download", repo),
		http:    &http.Client{Timeout: 90 * time.Second},
		ttl:     5 * time.Minute,
	}
}

// LatestVersion returns the newest published agent version (release tag_name minus the
// "agent-v" prefix, e.g. "0.1.21"), resolved from the GitHub API and cached for 30
// minutes. Best-effort: on any failure it returns the last known value (or "" if never
// resolved), so the UI degrades to just showing the running version.
func (c *agentCache) LatestVersion(ctx context.Context) string {
	c.mu.Lock()
	if c.version != "" && time.Since(c.versionAt) < 30*time.Minute {
		v := c.version
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()

	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", c.repo)
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return c.version
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return c.version // keep last known
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.version
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body) != nil {
		return c.version
	}
	v := strings.TrimPrefix(strings.TrimPrefix(body.TagName, "agent-v"), "v")
	if v == "" {
		return c.version
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

// refreshLocked re-validates the cache against the release at most once per ttl. If the
// release's checksums.txt changed (new version) it wipes the cache so assets re-download.
func (c *agentCache) refreshLocked(ctx context.Context) error {
	if c.checksums == "" {
		// cold start — try to load a previously cached checksums.txt from disk.
		if b, e := os.ReadFile(filepath.Join(c.dir, "checksums.txt")); e == nil {
			c.checksums = string(b)
		}
	} else if time.Since(c.lastCheck) < c.ttl {
		return nil // still fresh
	}

	latest, err := c.fetch(ctx, "checksums.txt")
	if err != nil {
		if c.checksums != "" {
			return nil // release unreachable but we have a cached version — serve it
		}
		return fmt.Errorf("fetch checksums: %w", err)
	}
	c.lastCheck = time.Now()
	if string(latest) == c.checksums {
		return nil // unchanged
	}
	// New release (or first run): drop the whole cache and re-seed the marker.
	if err := os.RemoveAll(c.dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("purge cache: %w", err)
	}
	if err := os.MkdirAll(c.dir, 0o750); err != nil {
		return err
	}
	c.checksums = string(latest)
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

func (c *agentCache) fetch(ctx context.Context, name string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/"+name, nil)
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
