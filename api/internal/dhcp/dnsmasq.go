package dhcp

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"api/internal/helper"
)

// dnsmasqConfDir is where the api writes per-network dnsmasq configs. It is a named volume shared
// with the dnsmasq container (mounted there at /etc/dnsmasq.d), so no container-exec is needed.
const dnsmasqConfDir = "/dhcp-conf"

// dnsmasqContainer is restarted (via the socket-proxy, not exec) to reload config.
const dnsmasqContainer = "dnsmasq"

// dnsmasqConfPath returns the per-network config path and GUARANTEES it stays inside
// dnsmasqConfDir. iface is already validated (validIface forbids '/') before a network is
// persisted and is wrapped between a fixed prefix/suffix, so it cannot introduce a path
// separator — but this is a privileged file write, so we re-validate and assert containment at
// the boundary rather than trust the stored value. Fails closed: a bad iface yields an error, not
// a path that could escape the directory.
func dnsmasqConfPath(iface string) (string, error) {
	if !validIface(iface) {
		return "", fmt.Errorf("invalid interface name %q", iface)
	}
	p := filepath.Join(dnsmasqConfDir, "wgpanel-"+iface+".conf")
	if filepath.Dir(p) != dnsmasqConfDir {
		return "", fmt.Errorf("refusing dnsmasq path outside %s: %q", dnsmasqConfDir, p)
	}
	return p, nil
}

// renderDnsmasqConf builds the DHCP-only config for one network. port=0 means no DNS (AdGuard
// owns :53); clients are pointed at the gateway for DNS (option 6) and routing (option 3). In
// "approve" mode only reserved+approved MACs (tagged `known`) get a lease; everything else is
// ignored. In "auto" mode any device in the pool gets one.
func renderDnsmasqConf(n *Network, reservations []Client) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by wgpanel — do not edit. Network: %s (%s)\n", n.Iface, n.CIDR)
	// Global single-value keywords (port=0, …) live ONLY in the base conf. dnsmasq loads base +
	// this file together, so repeating one here is an "illegal repeated keyword" that crash-loops
	// the container. Keep this file to per-network directives only.
	fmt.Fprintf(&b, "interface=%s\n", n.Iface)
	b.WriteString("bind-interfaces\n") // never listen on other NICs (e.g. the WAN)
	b.WriteString("no-resolv\n")
	mask := netmaskOf(n.CIDR)
	fmt.Fprintf(&b, "dhcp-range=%s,%s,%s,%ds\n", n.PoolStart, n.PoolEnd, mask, n.LeaseSecs)
	fmt.Fprintf(&b, "dhcp-option=3,%s\n", n.GatewayIP) // default gateway = the box
	fmt.Fprintf(&b, "dhcp-option=6,%s\n", n.GatewayIP) // DNS = the box (AdGuard binds all NICs)
	if n.Domain != "" {
		fmt.Fprintf(&b, "domain=%s\n", n.Domain)
	}
	fmt.Fprintf(&b, "dhcp-leasefile=/var/lib/misc/wgpanel-%s.leases\n", n.Iface)

	// Reservations (validated MAC/IP/name). In approve mode they also carry set:known.
	tag := ""
	if n.Mode == "approve" {
		tag = "set:known,"
	}
	for _, c := range reservations {
		name := sanitizeDHCPName(c.Name)
		line := fmt.Sprintf("dhcp-host=%s,%s%s", strings.ToLower(c.MAC), tag, c.IP)
		if name != "" {
			line += "," + name
		}
		b.WriteString(line + "\n")
	}
	if n.Mode == "approve" {
		// Hand nothing to an unknown MAC until it's approved (gets a reservation → tag known).
		b.WriteString("dhcp-ignore=tag:!known\n")
	}
	return b.String()
}

// sanitizeDHCPName reduces a client name to a safe DNS label for the lease (no spaces/metachars,
// which could otherwise break the single-line dhcp-host directive).
func sanitizeDHCPName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var out strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			out.WriteRune(r)
		} else if r == ' ' || r == '_' {
			out.WriteRune('-')
		}
	}
	s := strings.Trim(out.String(), "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

// writeDnsmasqConfig validates the generated config with `dnsmasq --test` BEFORE placing it
// (mirrors the nft -c gate), then writes it and reloads dnsmasq. A config that fails the test is
// never written, so a bad entry can't take DHCP down.
func (s *Service) writeDnsmasqConfig(n *Network) error {
	path, err := dnsmasqConfPath(n.Iface)
	if err != nil {
		return err
	}
	reservations, err := s.approvedReservations(n.ID)
	if err != nil {
		return err
	}
	content := renderDnsmasqConf(n, reservations)
	if err := dnsmasqTest(content); err != nil {
		return fmt.Errorf("generated dnsmasq config is invalid (not applied): %w", err)
	}
	if err := os.MkdirAll(dnsmasqConfDir, 0o755); err != nil {
		return fmt.Errorf("dnsmasq conf dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write dnsmasq config: %w", err)
	}
	return reloadDnsmasq()
}

// writeDnsmasqDisabled removes a network's config and reloads (used when a network is disabled
// or deleted).
func (s *Service) writeDnsmasqDisabled(n *Network) error {
	path, err := dnsmasqConfPath(n.Iface)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove dnsmasq config: %w", err)
		}
	}
	return reloadDnsmasq()
}

// dnsmasqBaseGlobals mirrors the GLOBAL directives in containers/dnsmasq/dnsmasq.base.conf. Keep
// it in sync with that file. dnsmasqTest prepends these so a candidate is validated the way
// dnsmasq actually loads it (base globals + conf-dir), not in isolation.
const dnsmasqBaseGlobals = "port=0\n"

// dnsmasqTest validates the candidate the SAME way the container loads it: a base conf carrying
// the globals + a conf-dir that pulls the candidate in. Testing the file alone (as this used to)
// misses a per-network file that repeats a base global like `port` — which passes `--test` solo
// but makes the running dnsmasq error "illegal repeated keyword" and crash-loop. The binary is in
// the api image (dnsmasq-base); --test only checks the config, it does not bind or touch a NIC.
func dnsmasqTest(content string) error {
	dir, err := os.MkdirTemp("", "wgpanel-dnsmasq")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "wgpanel-candidate.conf"), []byte(content), 0o600); err != nil {
		return err
	}
	base := filepath.Join(dir, "base.conf")
	// conf-dir matches wgpanel-*.conf so it pulls the candidate but not base.conf itself.
	if err := os.WriteFile(base, []byte(dnsmasqBaseGlobals+"conf-dir="+dir+",wgpanel-*.conf\n"), 0o600); err != nil {
		return err
	}
	out, err := exec.Command("dnsmasq", "--test", "--conf-file="+base).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// reloadDnsmasq restarts the dnsmasq container through the docker-socket-proxy (POST, allowed),
// never docker-exec. A fresh start re-reads every conf file; leases persist in the lease files.
func reloadDnsmasq() error {
	client := helper.NewDockerHTTPClientWithTimeout(20 * time.Second)
	// dnsmasqContainer is a compile-time constant, so no name-injection surface here.
	resp, err := client.Post("http://localhost/containers/"+dnsmasqContainer+"/restart", "application/json", nil)
	if err != nil {
		return fmt.Errorf("reload dnsmasq: %w", err)
	}
	defer resp.Body.Close()
	// 204 = restarted, 304 = already in desired state; a 404 means the container isn't deployed.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		return fmt.Errorf("reload dnsmasq: docker returned %d", resp.StatusCode)
	}
	return nil
}

func netmaskOf(cidr string) string {
	ones, _ := prefixLen(cidr)
	m := make([]byte, 4)
	for i := 0; i < 4; i++ {
		bits := ones - i*8
		if bits >= 8 {
			m[i] = 255
		} else if bits > 0 {
			m[i] = byte(0xff << uint(8-bits))
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}
