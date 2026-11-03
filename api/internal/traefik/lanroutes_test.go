package traefik

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A private route LAN devices may use gets its own gate (the trusted networks plus those devices)
// in place of the shared VPN-only one, answering as that one did; every other route is untouched.
func TestLANSentinelReplacesSharedGate(t *testing.T) {
	t.Setenv("WG_IP_RANGE", "10.8.0.0/24")
	t.Setenv("HEADSCALE_IP_RANGE", "100.64.0.0/10")
	dir := t.TempDir()
	routes := []DomainRouteConfig{
		{Domain: "git.example.com", TargetIP: "10.8.0.9", TargetPort: 3000, AccessMode: "vpn",
			Middlewares: []string{MiddlewareSentinelVPNSilentFile, "rate-limit@file"}, LANSources: []string{"10.20.20.51", "not-an-ip", "0.0.0.0"}},
		{Domain: "wiki.example.com", TargetIP: "10.8.0.9", TargetPort: 80, AccessMode: "vpn",
			Middlewares: []string{MiddlewareSentinelVPNFile}},
		{Domain: "www.example.com", TargetIP: "10.8.0.9", TargetPort: 80, AccessMode: "public",
			LANSources: []string{"10.20.20.51"}},
	}
	if err := GenerateDomainRoutes(dir, routes, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "domains.yml"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	router := func(name string) string {
		i := strings.Index(out, "    domain-"+name+":\n")
		if i < 0 {
			t.Fatalf("router %s missing:\n%s", name, out)
		}
		rest := out[i+1:]
		if j := strings.Index(rest, "\n    domain-"); j >= 0 {
			rest = rest[:j]
		}
		if j := strings.Index(rest, "\n  services:"); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}

	git := router("git-example-com")
	if strings.Contains(git, "sentinel_vpn") || !strings.Contains(git, "sentinel_lan-git-example-com") || !strings.Contains(git, "rate-limit@file") {
		t.Fatalf("git must swap the shared gate for its own, keeping the rest:\n%s", git)
	}
	mw := out[strings.Index(out, "    sentinel_lan-git-example-com:"):]
	for _, want := range []string{`"10.8.0.0/24"`, `"100.64.0.0/10"`, `"10.20.20.51/32"`, `errorMode: "silent"`} {
		if !strings.Contains(mw, want) {
			t.Fatalf("git's gate misses %s:\n%s", want, mw)
		}
	}
	if strings.Contains(out, "not-an-ip") || strings.Contains(out, "0.0.0.0/32") {
		t.Fatalf("an invalid LAN address was written:\n%s", out)
	}
	if wiki := router("wiki-example-com"); !strings.Contains(wiki, MiddlewareSentinelVPNFile) || strings.Contains(wiki, "sentinel_lan") {
		t.Fatalf("a route without LAN access keeps the shared gate:\n%s", wiki)
	}
	if www := router("www-example-com"); strings.Contains(www, "sentinel_lan") {
		t.Fatalf("a public route gets no LAN gate:\n%s", www)
	}
}
