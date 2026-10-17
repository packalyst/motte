package dhcp

import (
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// netplanDir is the HOST path where the panel writes its managed drop-ins (reached via nsenter,
// since the api container has its own filesystem). One file per managed interface.
const netplanDir = "/etc/netplan"

// nsenterHost runs a command inside the host namespaces (mount/uts/ipc/net/pid of PID 1) — the
// same pattern the rest of the panel uses for host-filesystem/systemd operations. Never a shell.
var nsenterHost = []string{"-t", "1", "-m", "-u", "-i", "-n", "-p", "--"}

// applyMu serializes interface changes so two saves can't race the bring-up/rollback.
var applyMu sync.Mutex

func dropInPath(iface string) string { return netplanDir + "/90-wgpanel-" + iface + ".yaml" }

// renderNetplan is the persisted drop-in: a static gateway address on the segment interface with
// DHCP-client OFF (the box is the gateway, not a client). Survives reboot. Not applied live with
// `netplan apply` (that would re-touch every NIC); we validate it parse-only and bring the
// address up scoped to this one interface instead.
func renderNetplan(n *Network) (string, error) {
	ones, err := prefixLen(n.CIDR)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`# Managed by wgpanel — do not edit by hand.
# Owns the gateway address for the %q private network; deleting this file disables it at reboot.
network:
  version: 2
  ethernets:
    %q:
      dhcp4: false
      dhcp6: false
      accept-ra: false
      addresses:
        - "%s/%d"
`, n.CIDR, n.Iface, n.GatewayIP, ones), nil
}

// ApplyNetwork makes the gateway address live and persistent with full rollback safety:
//
//	snapshot drop-in → write+validate drop-in (netplan generate, parse-only) →
//	`ip addr replace` (scoped to THIS interface — cannot touch the WAN) → `ip link up` →
//	health-check the address is live → roll back everything on any failure.
//
// It never runs `netplan apply`, so a bad config can only ever affect this one interface.
func (s *Service) ApplyNetwork(n *Network) error {
	applyMu.Lock()
	defer applyMu.Unlock()

	content, err := renderNetplan(n)
	if err != nil {
		return err
	}
	ones, _ := prefixLen(n.CIDR)
	addr := fmt.Sprintf("%s/%d", n.GatewayIP, ones)
	path := dropInPath(n.Iface)

	prev, hadPrev := hostReadFile(path)
	rollback := func(cause error) error {
		_ = ipCmd("addr", "del", addr, "dev", n.Iface) // undo the address we set
		if hadPrev {
			_ = hostWriteFile(path, string(prev))
		} else {
			_ = hostRemoveFile(path)
		}
		if out, e := hostNetplan("generate"); e != nil {
			log.Printf("dhcp: rollback netplan generate failed: %v (%s)", e, out)
		}
		return cause
	}

	// 1. Persist + validate the drop-in (parse-only; does NOT reconfigure anything live).
	if err := hostWriteFile(path, content); err != nil {
		return fmt.Errorf("write host netplan drop-in: %w", err)
	}
	_ = hostChmod(path, "0600")
	if out, err := hostNetplan("generate"); err != nil {
		return rollback(fmt.Errorf("netplan validation failed: %v (%s)", err, strings.TrimSpace(out)))
	}

	// 2. Bring the address up, scoped to this one interface.
	if err := ipCmd("addr", "replace", addr, "dev", n.Iface); err != nil {
		return rollback(fmt.Errorf("could not set %s on %s: %w", addr, n.Iface, err))
	}
	if err := ipCmd("link", "set", "dev", n.Iface, "up"); err != nil {
		return rollback(fmt.Errorf("could not bring %s up: %w", n.Iface, err))
	}

	// 3. Confirm it actually took.
	if err := gatewayLive(n.Iface, n.GatewayIP); err != nil {
		return rollback(fmt.Errorf("interface health-check failed, rolled back: %w", err))
	}
	return nil
}

// RemoveNetwork deletes the managed drop-in and removes the live gateway address (scoped).
func (s *Service) RemoveNetwork(n *Network) error {
	applyMu.Lock()
	defer applyMu.Unlock()

	if ones, err := prefixLen(n.CIDR); err == nil {
		_ = ipCmd("addr", "del", fmt.Sprintf("%s/%d", n.GatewayIP, ones), "dev", n.Iface)
	}
	path := dropInPath(n.Iface)
	if _, had := hostReadFile(path); had {
		if err := hostRemoveFile(path); err != nil {
			return fmt.Errorf("remove host netplan drop-in: %w", err)
		}
		if out, err := hostNetplan("generate"); err != nil {
			return fmt.Errorf("netplan validation failed after removal: %v (%s)", err, strings.TrimSpace(out))
		}
	}
	return nil
}

// InterfaceReady fails closed: dnsmasq must not serve a network whose interface drifted away
// (operator deleted the NIC or hand-edited netplan) — the drop-in must exist AND the gateway
// address must be live right now.
func (s *Service) InterfaceReady(n *Network) error {
	if _, had := hostReadFile(dropInPath(n.Iface)); !had {
		return fmt.Errorf("managed netplan drop-in for %s is missing — re-save the network", n.Iface)
	}
	return gatewayLive(n.Iface, n.GatewayIP)
}

// netplanConflict reports whether the interface is already defined in a netplan file the panel
// does NOT own (i.e. a hand-written stanza), returning that filename. It's a pre-save warning so
// an operator doesn't end up with two definitions fighting over one NIC. Text-scan heuristic (no
// YAML dep): a non-wgpanel file with a line whose key is "<iface>:". Best-effort — empty on any
// read error (the netplan generate during ApplyNetwork is still the hard validity gate).
func netplanConflict(iface string) string {
	out, err := exec.Command("nsenter", append(append([]string{}, nsenterHost...), "ls", "-1", netplanDir)...).Output()
	if err != nil {
		return ""
	}
	ownDropIn := "90-wgpanel-" + iface + ".yaml"
	for _, f := range strings.Fields(string(out)) {
		if !strings.HasSuffix(f, ".yaml") && !strings.HasSuffix(f, ".yml") {
			continue
		}
		if f == ownDropIn {
			continue // our own managed drop-in isn't a conflict
		}
		content, ok := hostReadFile(netplanDir + "/" + f)
		if !ok {
			continue
		}
		for _, line := range strings.Split(string(content), "\n") {
			// Normalize: trim indentation and surrounding quotes netplan allows on keys.
			key := strings.TrimSpace(line)
			key = strings.TrimPrefix(key, "\"")
			if key == iface+":" || key == iface+"\":" || strings.HasPrefix(key, iface+":") {
				return f
			}
		}
	}
	return ""
}

// gatewayLive checks the gateway address is assigned to the interface right now (ip runs
// directly — the container shares the host network namespace).
func gatewayLive(iface, gatewayIP string) error {
	out, err := exec.Command("ip", "-o", "-4", "addr", "show", "dev", iface).Output()
	if err != nil {
		return fmt.Errorf("interface %s not present", iface)
	}
	for _, tok := range strings.Fields(string(out)) {
		if host, _, e := net.ParseCIDR(tok); e == nil && host.String() == gatewayIP {
			return nil
		}
	}
	return fmt.Errorf("gateway %s not assigned to %s", gatewayIP, iface)
}

func prefixLen(cidr string) (int, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("invalid CIDR: %v", err)
	}
	ones, _ := ipnet.Mask.Size()
	return ones, nil
}

// ipCmd runs `ip ...` directly on the host network stack (net namespace is shared).
func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func hostNetplan(args ...string) (string, error) {
	out, err := exec.Command("nsenter", append(append([]string{}, nsenterHost...), append([]string{"netplan"}, args...)...)...).CombinedOutput()
	return string(out), err
}

func hostWriteFile(path, content string) error {
	cmd := exec.Command("nsenter", append(append([]string{}, nsenterHost...), "tee", path)...)
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = io.Discard
	return cmd.Run()
}

func hostReadFile(path string) ([]byte, bool) {
	out, err := exec.Command("nsenter", append(append([]string{}, nsenterHost...), "cat", path)...).Output()
	if err != nil {
		return nil, false
	}
	return out, true
}

func hostRemoveFile(path string) error {
	return exec.Command("nsenter", append(append([]string{}, nsenterHost...), "rm", "-f", path)...).Run()
}

func hostChmod(path, mode string) error {
	return exec.Command("nsenter", append(append([]string{}, nsenterHost...), "chmod", mode, path)...).Run()
}
