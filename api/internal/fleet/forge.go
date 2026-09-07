package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Forge abstracts a git-hosting provider's release-asset URL scheme and "latest release"
// lookup, so the panel can serve agent binaries from GitHub, Gitea/Forgejo, or a self-hosted
// GitLab without any provider-specific logic leaking into the cache layer. The repo identity
// comes entirely from the environment (SOURCE_REPO + SOURCE_FORGE) — nothing about a
// particular repo is baked into the binary.
//
// SECURITY: every value that flows into a URL (host, owner, repo, tag, asset) is validated
// against a strict allowlist BEFORE use, and each path segment is percent-escaped. A release
// tag is returned by the (untrusted) forge, so it is re-validated on the way out of
// LatestTag — a compromised or hostile forge cannot return "../.." or an absolute URL to
// redirect a download. Only https is ever spoken.
type Forge interface {
	// AssetURL returns the download URL for a named release asset at the given tag.
	// The caller is responsible for having obtained tag from LatestTag (already validated).
	AssetURL(tag, asset string) string
	// LatestTag returns the newest published release tag, validated against reTag.
	LatestTag(ctx context.Context, h *http.Client) (string, error)
}

// Forge type identifiers (SOURCE_FORGE values).
const (
	forgeGitHub = "github"
	forgeGitea  = "gitea"
	forgeGitLab = "gitlab"
)

var (
	// reSegment matches a single owner/repo path segment: starts alphanumeric, then
	// alphanumeric/._- , length-capped. Forbids "/", spaces, and "..".
	reSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	// reTag matches a release tag as returned by a forge. Same idea, also allowing '+'
	// (semver build metadata). Forbids "/", spaces, and "..".
	reTag = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`)
	// reHost matches a hostname with an optional port.
	reHost = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?(:[0-9]{1,5})?$`)
)

// forgeBase holds the validated identity shared by every driver.
type forgeBase struct {
	host  string // web host, e.g. github.com or git.example.com[:port]
	owner string
	repo  string
}

// newForge parses SOURCE_REPO (a full https URL like https://github.com/owner/repo) and the
// SOURCE_FORGE hint into a Forge driver. Strict and fail-closed: https only, exactly
// owner/repo, and a recognized or explicitly-set forge type (only github.com auto-detects).
func newForge(sourceURL, forgeType string) (Forge, error) {
	sourceURL = strings.TrimSpace(sourceURL)
	if sourceURL == "" {
		return nil, fmt.Errorf("SOURCE_REPO is empty")
	}
	u, err := url.Parse(sourceURL)
	if err != nil {
		return nil, fmt.Errorf("SOURCE_REPO is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("SOURCE_REPO must be an https URL (got scheme %q)", u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("SOURCE_REPO must not contain credentials")
	}
	host := u.Host
	if !reHost.MatchString(host) {
		return nil, fmt.Errorf("SOURCE_REPO host %q is invalid", host)
	}
	// Path must be exactly /owner/repo (a trailing .git is tolerated and stripped).
	p := strings.TrimSuffix(strings.Trim(u.EscapedPath(), "/"), ".git")
	parts := strings.Split(p, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("SOURCE_REPO path must be /owner/repo (got %q)", u.Path)
	}
	owner, repo := parts[0], parts[1]
	if !reSegment.MatchString(owner) || !reSegment.MatchString(repo) {
		return nil, fmt.Errorf("SOURCE_REPO owner/repo contains invalid characters")
	}
	base := forgeBase{host: host, owner: owner, repo: repo}

	ft := strings.ToLower(strings.TrimSpace(forgeType))
	if ft == "" {
		// Only github.com is safe to auto-detect. Never guess between gitea/gitlab/GHE —
		// a wrong guess would build wrong URLs, so fail closed and demand an explicit type.
		if strings.EqualFold(host, "github.com") {
			ft = forgeGitHub
		} else {
			return nil, fmt.Errorf("SOURCE_FORGE must be set (github|gitea|gitlab) for host %q", host)
		}
	}
	switch ft {
	case forgeGitHub:
		return &githubForge{base}, nil
	case forgeGitea:
		return &giteaForge{base}, nil
	case forgeGitLab:
		return &gitlabForge{base}, nil
	default:
		return nil, fmt.Errorf("unknown SOURCE_FORGE %q (want github|gitea|gitlab)", ft)
	}
}

// webURL builds https://<host>/<segments...> with every segment percent-escaped. Segments
// have already passed reSegment/reTag validation; the escape is belt-and-suspenders so a
// value can never break out of its path position.
func (b forgeBase) webURL(segments ...string) string {
	esc := make([]string, len(segments))
	for i, s := range segments {
		esc[i] = url.PathEscape(s)
	}
	return "https://" + b.host + "/" + strings.Join(esc, "/")
}

// fetchLatestTag GETs a forge release-JSON endpoint and returns a strictly-validated
// tag_name. All three forges expose tag_name on their "latest release" object.
func fetchLatestTag(ctx context.Context, h *http.Client, apiURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := h.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET latest release: %s", resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("decode release json: %w", err)
	}
	tag := strings.TrimSpace(body.TagName)
	if !reTag.MatchString(tag) {
		// Reject anything that could manipulate a later AssetURL (path traversal, empty).
		return "", fmt.Errorf("forge returned an invalid release tag")
	}
	return tag, nil
}

// --- GitHub (github.com and GitHub Enterprise) ---

type githubForge struct{ forgeBase }

func (f *githubForge) AssetURL(tag, asset string) string {
	return f.webURL(f.owner, f.repo, "releases", "download", tag, asset)
}

func (f *githubForge) LatestTag(ctx context.Context, h *http.Client) (string, error) {
	return fetchLatestTag(ctx, h, f.latestTagURL())
}

func (f *githubForge) latestTagURL() string {
	// github.com uses the dedicated api.github.com host; GitHub Enterprise serves the API
	// under /api/v3 on the same host.
	api := "https://api.github.com"
	if !strings.EqualFold(f.host, "github.com") {
		api = "https://" + f.host + "/api/v3"
	}
	return api + "/repos/" + url.PathEscape(f.owner) + "/" + url.PathEscape(f.repo) + "/releases/latest"
}

// --- Gitea / Forgejo ---

type giteaForge struct{ forgeBase }

func (f *giteaForge) AssetURL(tag, asset string) string {
	// Same public download scheme as GitHub.
	return f.webURL(f.owner, f.repo, "releases", "download", tag, asset)
}

func (f *giteaForge) LatestTag(ctx context.Context, h *http.Client) (string, error) {
	return fetchLatestTag(ctx, h, f.latestTagURL())
}

func (f *giteaForge) latestTagURL() string {
	return "https://" + f.host + "/api/v1/repos/" + url.PathEscape(f.owner) + "/" + url.PathEscape(f.repo) + "/releases/latest"
}

// --- GitLab (self-managed or gitlab.com) ---

type gitlabForge struct{ forgeBase }

func (f *gitlabForge) AssetURL(tag, asset string) string {
	// GitLab serves release "direct asset links" under /-/releases/<tag>/downloads/<path>.
	return f.webURL(f.owner, f.repo, "-", "releases", tag, "downloads", asset)
}

func (f *gitlabForge) LatestTag(ctx context.Context, h *http.Client) (string, error) {
	return fetchLatestTag(ctx, h, f.latestTagURL())
}

func (f *gitlabForge) latestTagURL() string {
	// GitLab addresses a project by its URL-encoded "owner/repo" path.
	proj := url.PathEscape(f.owner + "/" + f.repo) // -> owner%2Frepo
	return "https://" + f.host + "/api/v4/projects/" + proj + "/releases/permalink/latest"
}
