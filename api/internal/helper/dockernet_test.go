package helper

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// canForge: Docker keeps NET_RAW by default, so only a container that drops it (or everything),
// and isn't given NET_ADMIN or NET_RAW back, can't send from another container's address.
func TestCanForge(t *testing.T) {
	for _, c := range []struct {
		add, drop []string
		want      bool
	}{
		{nil, nil, true},                               // Docker's defaults include NET_RAW
		{nil, []string{"NET_RAW"}, false},              // dropped
		{nil, []string{"ALL"}, false},                  // everything dropped
		{nil, []string{"CAP_NET_RAW"}, false},          // the CAP_ spelling
		{nil, []string{"net_raw"}, false},              // any case
		{[]string{"NET_ADMIN"}, []string{"ALL"}, true}, // can take the address
		{[]string{"NET_RAW"}, []string{"ALL"}, true},   // given back
		{[]string{"ALL"}, []string{"NET_RAW"}, true},   // everything given
		{[]string{"NET_BIND_SERVICE"}, []string{"ALL"}, false},
		{nil, []string{"CHOWN"}, true}, // dropping something else changes nothing
	} {
		if got := canForge(c.add, c.drop); got != c.want {
			t.Errorf("canForge(%v, %v) = %v, want %v", c.add, c.drop, got, c.want)
		}
	}
}

// Every compose service on the stack's network other than Traefik must be unable to forge
// Traefik's address, or the panel keeps every domain route to a LAN device shut at runtime.
func TestComposeVPNNetworkCannotForge(t *testing.T) {
	b, err := os.ReadFile("../../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Networks   yaml.Node `yaml:"networks"`
			CapAdd     []string  `yaml:"cap_add"`
			CapDrop    []string  `yaml:"cap_drop"`
			Privileged bool      `yaml:"privileged"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	onNetwork := func(n yaml.Node) bool {
		switch n.Kind {
		case yaml.SequenceNode:
			for _, c := range n.Content {
				if c.Value == DockerNetwork {
					return true
				}
			}
		case yaml.MappingNode:
			for i := 0; i < len(n.Content); i += 2 {
				if n.Content[i].Value == DockerNetwork {
					return true
				}
			}
		}
		return false
	}
	seen := 0
	for name, svc := range doc.Services {
		if !onNetwork(svc.Networks) || name == "traefik" {
			continue
		}
		seen++
		if svc.Privileged || canForge(svc.CapAdd, svc.CapDrop) {
			t.Errorf("service %q on %s could forge Traefik's address: drop NET_RAW, no NET_ADMIN or privileged", name, DockerNetwork)
		}
	}
	if seen == 0 {
		t.Fatalf("no service besides traefik found on %s: the compose file layout changed", DockerNetwork)
	}
}
