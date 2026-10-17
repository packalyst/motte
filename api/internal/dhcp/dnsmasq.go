package dhcp

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"api/internal/helper"
)

// dnsmasqConfDir is where the api writes per-network dnsmasq configs. It is a named volume shared
// with the dnsmasq container (mounted there at /etc/dnsmasq.d), so no container-exec is needed.
const dnsmasqConfDir = "/dhcp-conf"

// dnsmasqContainer is restarted (via the socket-proxy, not exec) to reload config.
const dnsmasqContainer = "dnsmasq"

func dnsmasqConfPath(iface string) string { return dnsmasqConfDir + "/wgpanel-" + iface + ".conf" }

// renderDnsmasqConf builds the DHCP-only config for one network. port=0 means no DNS (AdGuard
// owns :53); clients are pointed at the gateway for DNS (option 6) and routing (option 3). In
// "approve" mode only reserved+approved MACs (tagged `known`) get a lease; everything else is
// ignored. In "auto" mode any device in the pool gets one.
func renderDnsmasqConf(n *Network, reservations []Client) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by wgpanel — do not edit. Network: %s (%s)\n", n.Iface, n.CIDR)
	b.WriteString("port=0\n") // DHCP only; AdGuard keeps :53
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
	if err := os.WriteFile(dnsmasqConfPath(n.Iface), []byte(content), 0o644); err != nil {
		return fmt.Errorf("write dnsmasq config: %w", err)
	}
	return reloadDnsmasq()
}

// writeDnsmasqDisabled removes a network's config and reloads (used when a network is disabled
// or deleted).
func (s *Service) writeDnsmasqDisabled(n *Network) error {
	path := dnsmasqConfPath(n.Iface)
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove dnsmasq config: %w", err)
		}
	}
	return reloadDnsmasq()
}

// dnsmasqTest runs `dnsmasq --test` against the candidate config in isolation. The binary is in
// the api image (dnsmasq-base); --test only checks syntax, it does not bind or touch the NIC.
func dnsmasqTest(content string) error {
	f, err := os.CreateTemp("", "wgpanel-dnsmasq-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	f.Close()
	out, err := exec.Command("dnsmasq", "--test", "--conf-file="+f.Name()).CombinedOutput()
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
