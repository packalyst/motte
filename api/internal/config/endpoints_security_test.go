package config

import (
	"encoding/json"
	"os"
	"testing"
)

// TestSecretEndpointsRequireAdmin guards against a regression where a secret-returning GET is
// left at the viewer-by-default policy and becomes readable by the lowest-trust role. These
// endpoints emit private keys / join secrets / provider credentials and must stay admin+.
// (Found in the 2026-10-19 RBAC audit.)
func TestSecretEndpointsRequireAdmin(t *testing.T) {
	raw, err := os.ReadFile("../../configs/endpoints.json")
	if err != nil {
		t.Fatalf("read endpoints.json: %v", err)
	}
	var doc struct {
		Services map[string]struct {
			Endpoints []struct {
				Path    string `json:"path"`
				Handler string `json:"handler"`
				MinRole string `json:"min_role"`
			} `json:"endpoints"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse endpoints.json: %v", err)
	}

	// service -> handler that must be admin-only.
	required := map[string]map[string]bool{
		"wireguard":    {"GetPeerConfig": true, "GetPeerQR": true},
		"headscale":    {"GetKeys": true},
		"turbotunnels": {"GetConfig": true},
	}
	for svc, handlers := range required {
		s, ok := doc.Services[svc]
		if !ok {
			t.Errorf("service %q missing from endpoints.json", svc)
			continue
		}
		seen := map[string]bool{}
		for _, e := range s.Endpoints {
			if handlers[e.Handler] && e.MinRole != "admin" && e.MinRole != "owner" {
				t.Errorf("%s/%s (%s) returns secrets but min_role=%q, want admin/owner", svc, e.Handler, e.Path, e.MinRole)
			}
			seen[e.Handler] = true
		}
		for h := range handlers { // a renamed handler must not slip out of this check
			if !seen[h] {
				t.Errorf("%s/%s is not in endpoints.json; update this list", svc, h)
			}
		}
	}
}

// TestEveryServiceEnabled guards against a service block that omits "enabled": true. The field
// defaults to Go's false, so a missing flag makes the router silently skip the whole service —
// every one of its routes 404s with no error. (Found when alerts 404'd on 2026-10-19.)
func TestEveryServiceEnabled(t *testing.T) {
	raw, err := os.ReadFile("../../configs/endpoints.json")
	if err != nil {
		t.Fatalf("read endpoints.json: %v", err)
	}
	var doc struct {
		Services map[string]struct {
			Enabled bool `json:"enabled"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse endpoints.json: %v", err)
	}
	for name, svc := range doc.Services {
		if !svc.Enabled {
			t.Errorf("service %q is missing \"enabled\": true — the router will skip it and all its routes 404", name)
		}
	}
}
