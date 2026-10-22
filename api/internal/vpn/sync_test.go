package vpn

import (
	"sort"
	"testing"
)

func TestStaleClientsOnlyPrunesSourcesThatAnswered(t *testing.T) {
	typeOf := map[string]string{
		"10.0.0.2": "wireguard", "10.0.0.3": "wireguard",
		"100.64.0.1": "headscale", "100.64.0.2": "headscale",
	}
	cases := []struct {
		name   string
		seen   map[string]bool
		listed map[string]int
		want   []string
	}{
		{"headscale unreachable: keep every headscale client",
			map[string]bool{"10.0.0.2": true, "10.0.0.3": true}, map[string]int{"wireguard": 2}, nil},
		{"wireguard failed to start: keep every peer",
			map[string]bool{"100.64.0.1": true, "100.64.0.2": true}, map[string]int{"headscale": 2}, nil},
		{"source answered empty while clients are stored: keep them",
			map[string]bool{"10.0.0.2": true, "10.0.0.3": true}, map[string]int{"wireguard": 2, "headscale": 0}, nil},
		{"node really removed: prune just it",
			map[string]bool{"10.0.0.2": true, "10.0.0.3": true, "100.64.0.1": true}, map[string]int{"wireguard": 2, "headscale": 1},
			[]string{"100.64.0.2"}},
	}
	for _, c := range cases {
		got := staleClients(typeOf, c.seen, c.listed)
		sort.Strings(got)
		if len(got) != len(c.want) || (len(got) > 0 && got[0] != c.want[0]) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
