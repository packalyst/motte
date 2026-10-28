package helper

import "testing"

func TestAlwaysPrivatePort(t *testing.T) {
	t.Setenv("API_PORT", "18081")
	for _, c := range []struct {
		port  int
		proto string
		want  bool
	}{{18081, "tcp", true}, {18081, "both", true}, {18081, "udp", false}, {443, "tcp", false}} {
		if got := AlwaysPrivatePort(c.port, c.proto); got != c.want {
			t.Errorf("AlwaysPrivatePort(%d, %s) = %v, want %v", c.port, c.proto, got, c.want)
		}
	}
	t.Setenv("API_PORT", "")
	if AlwaysPrivatePort(18081, "tcp") {
		t.Error("no API_PORT: nothing is pinned")
	}
	t.Setenv("API_PORT", "18081")
	found := false
	for _, p := range BuildEssentialPorts() {
		found = found || (p.Port == 18081 && p.Protocol == "tcp")
	}
	if !found {
		t.Error("the API port is not an essential port")
	}
}
