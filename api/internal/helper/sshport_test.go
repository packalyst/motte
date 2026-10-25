package helper

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseSSHDTPorts(t *testing.T) {
	out := "port 2297\naddressfamily any\nlistenaddress [::]:2297\nlistenaddress 0.0.0.0:2297\nlistenaddress 10.0.0.1:2200\nport 22\n"
	if got, want := parseSSHDTPorts(out), []int{2297, 2200, 22}; !slices.Equal(got, want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
}

// The port can sit in a drop-in (Ubuntu's sshd_config.d), in any case or separator, and sshd
// takes every Port line.
func TestConfigPortsFollowsIncludes(t *testing.T) {
	root := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n#Port 22\nPermitRootLogin no\nport\t2222\nMatch User backup\n  Port 9999\n")
	write("etc/ssh/sshd_config.d/50-port.conf", "Port=2297\n")
	write("etc/ssh/sshd_config.d/60-extra.conf", "  PORT 2297\n")
	if got, want := configPorts(root, "/etc/ssh/sshd_config", 0), []int{2297, 2222}; !slices.Equal(got, want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
}

func TestConfigPortsNoneFound(t *testing.T) {
	root := t.TempDir()
	if got := configPorts(root, "/etc/ssh/sshd_config", 0); len(got) != 0 {
		t.Fatalf("missing file gave %v", got)
	}
}

func TestHostListensTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	if !HostListensTCP(port) {
		t.Fatalf("listening port %d not seen", port)
	}
	l.Close()
	if HostListensTCP(port) {
		t.Fatalf("closed port %d still seen as listening", port)
	}
}
