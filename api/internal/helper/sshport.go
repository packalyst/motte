package helper

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The SSH port is what keeps the operator able to reach the host, so the firewall must never
// guess it. The api runs privileged in the host's PID namespace: it asks the host's sshd for
// its effective settings, which already apply every Include and sshd_config.d drop-in.

// hostRoot is where the host's filesystem is visible from the api container (its PID 1 is the
// host's init). Empty for a test or a process that runs on the host itself.
var hostRoot = "/proc/1/root"

// sshdTimeout bounds asking sshd for its configuration.
const sshdTimeout = 5 * time.Second

// SSHPorts returns every port the host's SSH server listens on: sshd's effective configuration
// (sshd -T on the host), else the config files read directly (Include and drop-ins followed),
// else 22 — the only case that is a guess, and logged as one.
func SSHPorts() []int {
	if ports, err := SSHDEffectivePorts(); err == nil && len(ports) > 0 {
		return ports
	} else if err != nil {
		log.Printf("ssh port: sshd -T on the host failed (%v); reading the config files", err)
	}
	root := hostRoot
	if _, err := os.Stat(filepath.Join(root, "etc/ssh/sshd_config")); err != nil {
		root = "" // not in the host's PID namespace: the mounted /etc/ssh/sshd_config is all there is
	}
	if ports := configPorts(root, "/etc/ssh/sshd_config", 0); len(ports) > 0 {
		return ports
	}
	log.Printf("ssh port: none found in sshd's settings or config files — assuming 22")
	return []int{22}
}

// GetSSHPort returns the host's (first) SSH port.
func GetSSHPort() int { return SSHPorts()[0] }

// SSHDEffectivePorts asks the host's sshd for its effective configuration (sshd -T) and returns
// its ports, including ports given on a ListenAddress.
func SSHDEffectivePorts() ([]int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshdTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nsenter", "-t", "1", "-m", "--", "sshd", "-T").Output()
	if err != nil {
		return nil, err
	}
	ports := parseSSHDTPorts(string(out))
	if len(ports) == 0 {
		return nil, fmt.Errorf("sshd -T reported no port")
	}
	return ports, nil
}

// parseSSHDTPorts reads the "port N" and "listenaddress host:N" lines of sshd -T output.
func parseSSHDTPorts(out string) []int {
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		switch key {
		case "port":
			ports = addPort(ports, val)
		case "listenaddress":
			if _, p, err := net.SplitHostPort(val); err == nil {
				ports = addPort(ports, p)
			}
		}
	}
	return ports
}

// configPorts reads the Port directives of an sshd config file under root, following Include
// (relative patterns are under /etc/ssh, as sshd resolves them). Port is cumulative in sshd, so
// every one counts. depth guards against an Include loop.
func configPorts(root, path string, depth int) []int {
	if depth > 8 {
		return nil
	}
	f, err := os.Open(filepath.Join(root, path))
	if err != nil {
		return nil
	}
	defer f.Close()
	var ports []int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "Keyword value", "Keyword=value" and "Keyword = value" are all valid.
		key, val, _ := strings.Cut(strings.Join(strings.Fields(strings.Replace(line, "=", " ", 1)), " "), " ")
		switch strings.ToLower(key) {
		case "port":
			ports = addPort(ports, val)
		case "include":
			for _, pattern := range strings.Fields(val) {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join("/etc/ssh", pattern)
				}
				matches, _ := filepath.Glob(filepath.Join(root, pattern))
				for _, m := range matches {
					for _, p := range configPorts(root, strings.TrimPrefix(m, root), depth+1) {
						ports = addPort(ports, strconv.Itoa(p))
					}
				}
			}
		case "match":
			return ports // settings after Match only apply to some connections; Port isn't allowed there
		}
	}
	return ports
}

// addPort appends a valid, not yet listed port.
func addPort(ports []int, s string) []int {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 || slices.Contains(ports, p) {
		return ports
	}
	return append(ports, p)
}

// HostListensTCP reports whether something on the host listens on TCP port (the api shares the
// host's network namespace, so /proc/net/tcp{,6} is the host's).
func HostListensTCP(port int) bool {
	want := fmt.Sprintf(":%04X", port)
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			// f[1] = local address "IP:PORT" (hex), f[3] = state; 0A = LISTEN.
			if len(f) > 3 && f[3] == "0A" && strings.HasSuffix(f[1], want) {
				return true
			}
		}
	}
	return false
}

// RestartSSH makes the host's SSH server pick up a changed sshd_config. On a host where systemd
// starts sshd from a socket (Ubuntu 22.10+), the listening port belongs to ssh.socket, generated
// from sshd_config on daemon-reload — so that socket is what has to restart.
func RestartSSH() error {
	host := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "nsenter", append([]string{"-t", "1", "-m", "-u", "-i", "-n", "-p", "--"}, args...)...).Run()
	}
	if host("systemctl", "is-active", "--quiet", "ssh.socket") == nil {
		if err := host("systemctl", "daemon-reload"); err != nil {
			return err
		}
		return host("systemctl", "restart", "ssh.socket")
	}
	if err := host("systemctl", "restart", "ssh"); err != nil {
		return host("systemctl", "restart", "sshd")
	}
	return nil
}
