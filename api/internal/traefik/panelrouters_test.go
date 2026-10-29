package traefik

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"api/internal/helper"
)

// renderCore builds core.yml from the real templates as manage.sh does (with ssl: the SSL routers
// inserted before the services section), with synthetic values.
func renderCore(t *testing.T, ssl bool) string {
	t.Helper()
	vars := map[string]string{
		"SERVER_IP": "198.51.100.10", "ADMIN_DOMAIN": "panel.vpn.test", "SSL_DOMAIN": "panel.example.test",
		"API_PORT": "8081", "HTTPS_PORT": "443", "RATE_LIMIT_AVERAGE": "100", "RATE_LIMIT_BURST": "200",
		"RATE_LIMIT_STRICT_AVERAGE": "10", "RATE_LIMIT_STRICT_BURST": "20",
		"VPN_SOURCE_RANGE": `            - "10.8.0.0/16"`,
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "traefik", name))
		if err != nil {
			t.Fatal(err)
		}
		return os.Expand(string(b), func(k string) string {
			v, ok := vars[k]
			if !ok {
				t.Fatalf("%s uses ${%s}, which this test doesn't set", name, k)
			}
			return v
		})
	}
	core := read("dynamic.yml.template")
	if ssl {
		// manage.sh drops the IP-host headscale-control-secure (the SSL routers bring their own)…
		start := strings.Index(core, "    headscale-control-secure:")
		end := start + strings.Index(core[start:], "tls: {}\n") + len("tls: {}\n")
		core = core[:start] + core[end:]
		// …then inserts the SSL routers before the services section.
		core = strings.Replace(core, "\n  services:", "\n"+read("dynamic-ssl-routers.yml.template")+"\n  services:", 1)
	}
	if strings.Count(core, "    headscale-control-secure:") > 1 {
		t.Fatal("duplicate router in the rendered config")
	}
	return core
}

func routerMiddlewares(t *testing.T, content, router string) []string {
	t.Helper()
	v, err := helper.GetYAMLPath(content, "http.routers."+router+".middlewares")
	if err != nil {
		t.Fatalf("router %s: %v", router, err)
	}
	var out []string
	for _, x := range v.([]interface{}) {
		out = append(out, x.(string))
	}
	return out
}

// Every router the VPN-only and block-list toggles name exists, and once both are on, every one
// carries both gates — on the HTTP redirect, ahead of the redirect (after it they'd never run).
func TestPanelRouterGates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.yml")
	if err := os.WriteFile(path, []byte(renderCore(t, true)), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Service{configPath: path}
	s.RestoreFWBlock(true)
	for _, r := range vpnOnlyRouters {
		if err := s.addMiddlewareToRouter(r, MiddlewareSentinelVPN); err != nil {
			t.Fatalf("vpn-only on %s: %v", r, err)
		}
	}
	b, _ := os.ReadFile(path)
	content := string(b)
	for _, r := range fwBlockRouters {
		mws := routerMiddlewares(t, content, r)
		has := map[string]bool{}
		for _, m := range mws {
			has[m] = true
		}
		if !has[MiddlewareSentinelFWBlock] || !has[MiddlewareSentinelVPN] {
			t.Errorf("%s: %v, want both gates", r, mws)
		}
		if has[MiddlewareRedirectHTTPS] && mws[len(mws)-1] != MiddlewareRedirectHTTPS {
			t.Errorf("%s: %v, the redirect must come last", r, mws)
		}
	}
	if mws := routerMiddlewares(t, content, "ui"); mws[len(mws)-1] != MiddlewareRedirectHTTPS {
		t.Fatalf("ui no longer redirects: %v", mws)
	}
}

// Nothing on plain HTTP serves the panel or its API: on the server IP / admin domain, only the
// Tailscale control paths are served; every other HTTP router redirects or drops.
func TestPanelNotServedOverHTTP(t *testing.T) {
	for _, ssl := range []bool{false, true} {
		content := renderCore(t, ssl)
		v, err := helper.GetYAMLPath(content, "http.routers")
		if err != nil {
			t.Fatal(err)
		}
		for name, r := range v.(map[string]interface{}) {
			router := r.(map[string]interface{})
			web := false
			for _, ep := range router["entryPoints"].([]interface{}) {
				web = web || ep == "web"
			}
			if !web || name == "headscale-control" {
				continue
			}
			mws := map[string]bool{}
			if list, ok := router["middlewares"].([]interface{}); ok {
				for _, m := range list {
					mws[m.(string)] = true
				}
			}
			if !mws[MiddlewareRedirectHTTPS] && !mws[MiddlewareSentinelDrop] {
				t.Errorf("ssl=%v: HTTP router %s serves content (middlewares %v)", ssl, name, router["middlewares"])
			}
		}
	}
}

// A site with HTTPS on only redirects on plain HTTP, after its own gates; one without HTTPS is
// still served there.
func TestDomainRouteHTTPRedirect(t *testing.T) {
	dir := t.TempDir()
	err := GenerateDomainRoutes(dir, []DomainRouteConfig{
		{Domain: "secure.example.test", TargetIP: "10.8.0.20", TargetPort: 8080, AccessMode: "public", FrontendSSL: true},
		{Domain: "plain.example.test", TargetIP: "10.8.0.21", TargetPort: 8080, AccessMode: "public"},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "domains.yml"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(b)
	secure := routerMiddlewares(t, content, "domain-"+helper.SanitizeDomainName("secure.example.test"))
	if secure[len(secure)-1] != MiddlewareRedirectHTTPS+"@file" || secure[0] != MiddlewareSentinelFWBlockFile {
		t.Fatalf("HTTPS site on HTTP: %v, want its gate then the redirect", secure)
	}
	for _, m := range routerMiddlewares(t, content, "domain-"+helper.SanitizeDomainName("secure.example.test")+"-secure") {
		if strings.HasPrefix(m, MiddlewareRedirectHTTPS) {
			t.Fatal("the HTTPS router redirects")
		}
	}
	for _, m := range routerMiddlewares(t, content, "domain-"+helper.SanitizeDomainName("plain.example.test")) {
		if strings.HasPrefix(m, MiddlewareRedirectHTTPS) {
			t.Fatal("a site without HTTPS is redirected")
		}
	}
}

// Every router that serves the panel or its API (not a drop) is one the VPN-only and block-list
// toggles cover, so a new panel router can't be left out of both.
func TestPanelRoutersAllGated(t *testing.T) {
	listed := map[string]bool{}
	for _, r := range fwBlockRouters {
		listed[r] = true
	}
	content := renderCore(t, true)
	v, err := helper.GetYAMLPath(content, "http.routers")
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range v.(map[string]interface{}) {
		router := r.(map[string]interface{})
		if svc := router["service"]; svc != "ui" && svc != "unified-api" {
			continue
		}
		drops := false
		if list, ok := router["middlewares"].([]interface{}); ok {
			for _, m := range list {
				drops = drops || m == MiddlewareSentinelDrop
			}
		}
		if !drops && name != "redirect-to-https" && !listed[name] {
			t.Errorf("panel router %s isn't covered by the VPN-only and block-list toggles", name)
		}
	}
}

// Every sentinel middleware that judges the visitor's IP (an allow list or the block list) takes
// the panel's live Cloudflare list, in the core config and in generated per-site ones; without it
// a visitor behind Cloudflare would be judged by Cloudflare's address.
func TestSentinelIPFiltersUseCloudflareList(t *testing.T) {
	check := func(where, content string) {
		v, err := helper.GetYAMLPath(content, "http.middlewares")
		if err != nil {
			t.Fatal(err)
		}
		for name, m := range v.(map[string]interface{}) {
			plugin, ok := m.(map[string]interface{})["plugin"].(map[string]interface{})
			if !ok {
				continue
			}
			s := plugin["sentinel"].(map[string]interface{})
			f, ok := s["ipFilter"].(map[string]interface{})
			if !ok || name == MiddlewareSentinelDrop { // drop admits nobody, whoever the visitor is
				continue
			}
			if s["cloudflareListUrl"] != "http://host.docker.internal:8081/internal/cloudflare" {
				t.Errorf("%s: %s judges IPs (%v) without the Cloudflare list", where, name, f)
			}
		}
	}
	check("core", renderCore(t, true))

	t.Setenv("API_PORT", "8081")
	dir := t.TempDir()
	if err := GenerateDomainRoutes(dir, []DomainRouteConfig{{Domain: "site.example.test", TargetIP: "10.8.0.30", TargetPort: 80,
		AccessMode: "vpn", SentinelConfig: &SentinelConfig{Enabled: true, ErrorMode: "403", IPFilter: struct {
			SourceRange []string `json:"sourceRange,omitempty"`
		}{SourceRange: []string{"10.8.0.0/16"}}}}}, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "domains.yml"))
	check("domains", string(b))
}
