package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/helper"
	"api/internal/router"
)

// The panel deploys by `git pull`, so its "version" is the commit it was built from and its
// "is there an update" check is: does the branch tip on SOURCE_REPO differ from that commit?
// We answer this with the git smart-HTTP protocol — a plain HTTPS GET of info/refs — which
// every forge (GitHub/Gitea/GitLab/bare) speaks identically. No git binary, no subprocess,
// so there is no ext::/file:// git-remote-helper command-execution surface; only https is
// contacted, and the result is cached to avoid hammering the remote.

var reSha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

type panelUpdateCache struct {
	mu        sync.Mutex
	latest    string // full remote tip sha
	checkedAt time.Time
	ok        bool
}

var panelUpd panelUpdateCache

// handlePanelUpdateCheck reports whether the branch tip on SOURCE_REPO is ahead of the
// commit this panel was built from. Best-effort: on any problem it returns checked=false so
// the About page simply shows the build without a staleness badge.
func (s *Service) handlePanelUpdateCheck(w http.ResponseWriter, r *http.Request) {
	current := strings.TrimSuffix(router.PanelVersion, "-dirty")
	repo := strings.TrimSpace(helper.GetEnvOptional("SOURCE_REPO", ""))
	if current == "" || current == "dev" || repo == "" {
		router.JSON(w, map[string]any{"current": router.PanelVersion, "checked": false})
		return
	}
	branch := strings.TrimSpace(router.PanelBranch)

	latest, ok := panelUpd.resolve(r.Context(), repo, branch)
	if !ok {
		router.JSON(w, map[string]any{"current": current, "checked": false})
		return
	}
	short := latest
	if len(short) > 7 {
		short = short[:7]
	}
	router.JSON(w, map[string]any{
		"current":    current,
		"latest":     short,
		"up_to_date": strings.HasPrefix(latest, current),
		"branch":     branch,
		"checked":    true,
		"checked_at": panelUpd.checkedAt.UTC().Format(time.RFC3339),
	})
}

// resolve returns the branch-tip sha, cached for 10 minutes. On a fetch error it keeps
// serving the last known-good value rather than flapping.
func (u *panelUpdateCache) resolve(ctx context.Context, repo, branch string) (string, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.ok && time.Since(u.checkedAt) < 10*time.Minute {
		return u.latest, true
	}
	sha, err := fetchRemoteTip(ctx, repo, branch)
	if err != nil {
		if u.ok {
			return u.latest, true // keep last known good
		}
		return "", false
	}
	u.latest, u.checkedAt, u.ok = sha, time.Now(), true
	return sha, true
}

// fetchRemoteTip GETs the git smart-HTTP ref advertisement and returns the tip sha of the
// deploy branch (or the remote's default HEAD when no branch is known). https only.
func fetchRemoteTip(ctx context.Context, repo, branch string) (string, error) {
	base, err := url.Parse(repo)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return "", fmt.Errorf("SOURCE_REPO must be an https URL")
	}
	endpoint := strings.TrimRight(repo, "/") + "/info/refs?service=git-upload-pack"

	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "git/2.0 (wire-panel)")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("info/refs HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return "", err
	}
	refs := parseGitRefs(body)
	if branch != "" {
		if sha, ok := refs["refs/heads/"+branch]; ok {
			return sha, nil
		}
	}
	if sha, ok := refs["HEAD"]; ok {
		return sha, nil
	}
	return "", fmt.Errorf("no matching ref in remote advertisement")
}

// parseGitRefs parses a git-upload-pack v1 ref advertisement (pkt-line framed) into a
// refname->sha map. Each pkt-line is a 4-hex length prefix followed by "<sha> <refname>",
// with capabilities after a NUL on the first ref line; a length of 0000 is a flush.
func parseGitRefs(body []byte) map[string]string {
	refs := map[string]string{}
	for i := 0; i+4 <= len(body); {
		n64, err := strconv.ParseInt(string(body[i:i+4]), 16, 32)
		if err != nil {
			break
		}
		n := int(n64)
		if n == 0 { // flush-pkt
			i += 4
			continue
		}
		if n < 4 || i+n > len(body) {
			break
		}
		line := strings.TrimRight(string(body[i+4:i+n]), "\n")
		i += n
		if strings.HasPrefix(line, "#") { // "# service=git-upload-pack"
			continue
		}
		if k := strings.IndexByte(line, 0); k >= 0 { // strip \0<capabilities>
			line = line[:k]
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 && reSha40.MatchString(parts[0]) {
			refs[parts[1]] = parts[0]
		}
	}
	return refs
}
