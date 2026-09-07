package fleet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewForgeValid: accepted configs resolve to the right driver + URL scheme.
func TestNewForgeValid(t *testing.T) {
	cases := []struct {
		url, forge string
		wantAsset  string // AssetURL("agent-v1.2.3", "wgscout-linux-amd64")
	}{
		{"https://github.com/packalyst/wireguard-admin-panel", "",
			"https://github.com/packalyst/wireguard-admin-panel/releases/download/agent-v1.2.3/wgscout-linux-amd64"},
		{"https://github.com/packalyst/wireguard-admin-panel.git", "github",
			"https://github.com/packalyst/wireguard-admin-panel/releases/download/agent-v1.2.3/wgscout-linux-amd64"},
		{"https://git.example.com/acme/panel", "gitea",
			"https://git.example.com/acme/panel/releases/download/agent-v1.2.3/wgscout-linux-amd64"},
		{"https://gitlab.example.com/acme/panel", "gitlab",
			"https://gitlab.example.com/acme/panel/-/releases/agent-v1.2.3/downloads/wgscout-linux-amd64"},
	}
	for _, c := range cases {
		f, err := newForge(c.url, c.forge)
		if err != nil {
			t.Fatalf("newForge(%q,%q) error: %v", c.url, c.forge, err)
		}
		if got := f.AssetURL("agent-v1.2.3", "wgscout-linux-amd64"); got != c.wantAsset {
			t.Errorf("AssetURL for %q = %q, want %q", c.url, got, c.wantAsset)
		}
	}
}

// TestNewForgeRejects: every fail-closed path is exercised.
func TestNewForgeRejects(t *testing.T) {
	cases := []struct{ name, url, forge string }{
		{"empty", "", "github"},
		{"http not https", "http://github.com/a/b", "github"},
		{"embedded credentials", "https://user:pw@github.com/a/b", "github"},
		{"missing repo segment", "https://github.com/onlyowner", "github"},
		{"nested path (3 segments)", "https://gitlab.example.com/group/sub/proj", "gitlab"},
		{"path traversal in repo", "https://github.com/a/..", "github"},
		{"space in owner", "https://github.com/a b/c", "github"},
		{"non-github host without forge", "https://git.example.com/a/b", ""},
		{"unknown forge type", "https://git.example.com/a/b", "svn"},
		{"garbage url", "://not a url", "github"},
	}
	for _, c := range cases {
		if _, err := newForge(c.url, c.forge); err == nil {
			t.Errorf("%s: newForge(%q,%q) should have failed", c.name, c.url, c.forge)
		}
	}
}

// TestForgeLatestTagURLs: each driver builds the correct per-forge API URL, including the
// GitHub Enterprise /api/v3 split and GitLab's URL-encoded project path.
func TestForgeLatestTagURLs(t *testing.T) {
	cases := []struct {
		f    interface{ latestTagURL() string }
		want string
	}{
		{&githubForge{forgeBase{"github.com", "acme", "panel"}},
			"https://api.github.com/repos/acme/panel/releases/latest"},
		{&githubForge{forgeBase{"ghe.corp.com", "acme", "panel"}}, // GitHub Enterprise
			"https://ghe.corp.com/api/v3/repos/acme/panel/releases/latest"},
		{&giteaForge{forgeBase{"git.example.com", "acme", "panel"}},
			"https://git.example.com/api/v1/repos/acme/panel/releases/latest"},
		{&gitlabForge{forgeBase{"gitlab.example.com", "acme", "panel"}},
			"https://gitlab.example.com/api/v4/projects/acme%2Fpanel/releases/permalink/latest"},
	}
	for _, c := range cases {
		if got := c.f.latestTagURL(); got != c.want {
			t.Errorf("latestTagURL = %q, want %q", got, c.want)
		}
	}
}

// TestFetchLatestTagValidatesTag: a hostile forge returning a traversal/empty tag is rejected.
func TestFetchLatestTagValidatesTag(t *testing.T) {
	for _, body := range []string{
		`{"tag_name":"../../etc"}`,
		`{"tag_name":""}`,
		`{"tag_name":"a/b"}`,
		`{"tag_name":"has space"}`,
		`not json`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		if _, err := fetchLatestTag(context.Background(), srv.Client(), srv.URL); err == nil {
			t.Errorf("fetchLatestTag should reject body %q", body)
		}
		srv.Close()
	}
}

// TestFetchLatestTagHTTPError: a non-200 is an error, not a silent empty tag.
func TestFetchLatestTagHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := fetchLatestTag(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Error("expected error on HTTP 404")
	}
}
