package traefik

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A route that names its backend host gets its own transport sending its domain (still checking
// the certificate unless it skips that); routes that only skip the check share one; a plain-HTTP
// or wildcard route never names a host.
func TestBackendTransports(t *testing.T) {
	dir := t.TempDir()
	routes := []DomainRouteConfig{
		{Domain: "tax.example.com", TargetIP: "10.8.0.9", TargetPort: 443, HTTPSBackend: true, BackendSNI: true},
		{Domain: "nas.example.com", TargetIP: "10.8.0.10", TargetPort: 443, HTTPSBackend: true, BackendSNI: true, SkipCertVerify: true},
		{Domain: "a.example.com", TargetIP: "10.8.0.11", TargetPort: 443, HTTPSBackend: true, SkipCertVerify: true},
		{Domain: "b.example.com", TargetIP: "10.8.0.12", TargetPort: 443, HTTPSBackend: true, SkipCertVerify: true},
		{Domain: "plain.example.com", TargetIP: "10.8.0.13", TargetPort: 80, BackendSNI: true, SkipCertVerify: true},
		{Domain: "*.example.org", TargetIP: "10.8.0.14", TargetPort: 443, HTTPSBackend: true, BackendSNI: true},
	}
	if err := GenerateDomainRoutes(dir, routes, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "domains.yml"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	service := func(name string) string {
		i := strings.Index(out, "    domain-"+name+"-svc:\n")
		if i < 0 {
			t.Fatalf("service %s missing:\n%s", name, out)
		}
		rest := out[i:]
		return rest[:strings.Index(rest, "\n\n")]
	}
	transports := out[strings.Index(out, "  serversTransports:\n"):]

	if s := service("tax-example-com"); !strings.Contains(s, "serversTransport: domain-tax-example-com-transport") {
		t.Fatalf("tax must use its own transport:\n%s", s)
	}
	if !strings.Contains(transports, "    domain-tax-example-com-transport:\n      serverName: \"tax.example.com\"\n    ") {
		t.Fatalf("tax must name its domain and keep checking the certificate:\n%s", transports)
	}
	if !strings.Contains(transports, "    domain-nas-example-com-transport:\n      serverName: \"nas.example.com\"\n      insecureSkipVerify: true\n") {
		t.Fatalf("nas must name its domain and skip the check:\n%s", transports)
	}
	for _, name := range []string{"a-example-com", "b-example-com"} {
		if s := service(name); !strings.Contains(s, "serversTransport: "+skipVerifyTransport) {
			t.Fatalf("%s must use the shared skip transport:\n%s", name, s)
		}
	}
	if n := strings.Count(transports, "    "+skipVerifyTransport+":\n"); n != 1 {
		t.Fatalf("the shared skip transport is written %d times:\n%s", n, transports)
	}
	for _, name := range []string{"plain-example-com", "wildcard-example-org"} {
		if strings.Contains(out, "domain-"+name+"-transport") {
			t.Fatalf("%s must not name a backend host:\n%s", name, out)
		}
	}
	if strings.Contains(out, `serverName: "*.`) {
		t.Fatalf("a wildcard was sent as a hostname:\n%s", out)
	}
}
