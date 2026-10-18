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
		"headscale":    {"GetPreAuthKeys": true},
		"turbotunnels": {"GetConfig": true},
	}
	for svc, handlers := range required {
		s, ok := doc.Services[svc]
		if !ok {
			t.Errorf("service %q missing from endpoints.json", svc)
			continue
		}
		for _, e := range s.Endpoints {
			if handlers[e.Handler] && e.MinRole != "admin" && e.MinRole != "owner" {
				t.Errorf("%s/%s (%s) returns secrets but min_role=%q, want admin/owner", svc, e.Handler, e.Path, e.MinRole)
			}
		}
	}
}
