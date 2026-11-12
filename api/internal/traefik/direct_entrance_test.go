package traefik

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// routerName starts a router block in the generated dynamic config (4-space indent).
var routerName = regexp.MustCompile(`(?m)^    ([a-z][a-z0-9-]*):$`)

// routersOn returns the routers in text that list entrance among their entryPoints.
func routersOn(text, entrance string) map[string]string {
	out := map[string]string{}
	idx := routerName.FindAllStringSubmatchIndex(text, -1)
	for i, m := range idx {
		end := len(text)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		block := text[m[0]:end]
		if strings.Contains(block, "\n        - "+entrance+"\n") {
			out[text[m[2]:m[3]]] = block
		}
	}
	return out
}

// The narrow "direct" entrance gets the HTTPS that is not from Cloudflare while Cloudflare-only
// is on, so it must serve only the DERP relay and the proxy-domain triggers and drop the rest;
// the normal entrances are the default, so a router naming none never lands there.
func TestDirectEntranceServesOnlyRelayAndTriggers(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	sslRouters, manage := read("traefik/dynamic-ssl-routers.yml.template"), read("manage.sh")

	got := routersOn(sslRouters, "direct")
	for name, block := range routersOn(manage, "direct") {
		got[name] = block
	}
	want := map[string]string{
		"derp-secure":         "rule: \"Host(`${SSL_DOMAIN}`) && PathPrefix(`/derp`)\"",
		"direct-drop":         "- sentinel_drop",
		"proxy-rotate-secure": "rule: \"Host(`${PROXY_DOMAIN}`) && (PathPrefix(`/api/restart`) || PathPrefix(`/api/hook`))\"",
	}
	for name, block := range got {
		if w, ok := want[name]; !ok {
			t.Errorf("router %s must not be on the direct entrance:\n%s", name, block)
		} else if !strings.Contains(block, w) {
			t.Errorf("router %s on the direct entrance must have %q:\n%s", name, w, block)
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("router %s missing from the direct entrance", name)
		}
	}
	if strings.Contains(read("traefik/dynamic.yml.template"), "- direct\n") {
		t.Error("the base config must put nothing on the direct entrance")
	}

	static := manage[strings.Index(manage, "# Traefik Static Configuration (SSL enabled)"):]
	static = static[:strings.Index(static, "\nEOF\n")]
	for _, w := range []string{
		"  web:\n    address: \":${HTTP_PORT}\"\n    asDefault: true\n",
		"  websecure:\n    address: \":${HTTPS_PORT}\"\n    asDefault: true\n",
		"  direct:\n    address: \":${TRAEFIK_DIRECT_PORT}\"\n",
	} {
		if !strings.Contains(static, w) {
			t.Errorf("static config missing %q:\n%s", w, static)
		}
	}
	if strings.Count(static, "asDefault: true") != 2 {
		t.Errorf("only web and websecure may be default entrances:\n%s", static)
	}
}
