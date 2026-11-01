package helper

import (
	"bufio"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// defaultRoute is the first default IPv4 route: its interface, gateway and (when the route pins
// one) source address.
type defaultRoute struct{ dev, via, src string }

// readDefaultRoute parses `ip -4 route show default`.
func readDefaultRoute() (defaultRoute, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return defaultRoute{}, err
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if r := parseRouteLine(sc.Text()); r.dev != "" {
			return r, nil
		}
	}
	return defaultRoute{}, fmt.Errorf("no default route found")
}

// parseRouteLine reads the dev, via and src fields of one `ip route` line.
func parseRouteLine(line string) defaultRoute {
	var r defaultRoute
	f := strings.Fields(line)
	for i := 0; i < len(f)-1; i++ {
		switch f[i] {
		case "dev":
			r.dev = f[i+1]
		case "via":
			r.via = f[i+1]
		case "src":
			r.src = f[i+1]
		}
	}
	return r
}

// DefaultRouteInterface returns the NIC that carries the default IPv4 route — the WAN /
// internet-facing interface. Shared by the firewall and DHCP packages so this detection lives in
// one place. Returns an error if the command fails or there is no default route.
func DefaultRouteInterface() (string, error) {
	r, err := readDefaultRoute()
	return r.dev, err
}

// WANAddresses returns the internet-facing interface, the address the server itself sends from
// on it (the default route's source, as the kernel picks it), and every IPv4 address on it.
func WANAddresses() (iface, hostSrc string, addrs []string, err error) {
	r, err := readDefaultRoute()
	if err != nil {
		return "", "", nil, err
	}
	hostSrc = r.src
	if hostSrc == "" {
		if net.ParseIP(r.via).To4() == nil {
			return "", "", nil, fmt.Errorf("the default route has no gateway, so the server's own address can't be told")
		}
		out, err := exec.Command("ip", "-4", "route", "get", r.via).Output()
		if err != nil {
			return "", "", nil, err
		}
		hostSrc = parseRouteLine(strings.SplitN(string(out), "\n", 2)[0]).src
	}
	if net.ParseIP(hostSrc).To4() == nil {
		return "", "", nil, fmt.Errorf("could not tell which address the server sends from")
	}
	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", r.dev).Output()
	if err != nil {
		return "", "", nil, err
	}
	return r.dev, hostSrc, parseAddrLines(string(out)), nil
}

// parseAddrLines reads the IPv4 addresses from `ip -4 -o addr show` output.
func parseAddrLines(out string) []string {
	var addrs []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i < len(f)-1; i++ {
			if f[i] != "inet" {
				continue
			}
			if ip, _, err := net.ParseCIDR(f[i+1]); err == nil && ip.To4() != nil {
				addrs = append(addrs, ip.String())
			}
		}
	}
	return addrs
}
