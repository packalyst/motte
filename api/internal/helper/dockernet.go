package helper

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
)

// defaultDockerSubnet matches .env.example, so a missing or garbled DOCKER_SUBNET still names the
// network the stack really runs on.
const defaultDockerSubnet = "172.18.0.0/24"

// DockerSubnet returns the stack's Docker network (DOCKER_SUBNET) as a masked IPv4 CIDR, or the
// install default when it is unset or not an IPv4 CIDR.
func DockerSubnet() string {
	if p, err := netip.ParsePrefix(strings.TrimSpace(os.Getenv("DOCKER_SUBNET"))); err == nil && p.Addr().Is4() {
		return p.Masked().String()
	}
	return defaultDockerSubnet
}

// TraefikOrigin returns where Traefik's traffic enters the host: the Docker bridge interface that
// carries DOCKER_SUBNET, and Traefik's own address on it (TRAEFIK_CONTAINER_IP). Both must check
// out — the address inside the subnet, and exactly one host interface on it — or an error is
// returned, so a rule keyed on them is never written against a guessed interface or address.
func TraefikOrigin() (iface string, ip netip.Addr, err error) {
	subnet := netip.MustParsePrefix(DockerSubnet())
	ip, err = netip.ParseAddr(strings.TrimSpace(os.Getenv("TRAEFIK_CONTAINER_IP")))
	if err != nil || !ip.Is4() || !subnet.Contains(ip) {
		return "", netip.Addr{}, errors.New("TRAEFIK_CONTAINER_IP is not an address inside DOCKER_SUBNET")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", netip.Addr{}, err
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			if host, _ := netip.AddrFromSlice(n.IP.To4()); subnet.Contains(host) {
				if iface != "" && iface != ifc.Name {
					return "", netip.Addr{}, errors.New("more than one host interface on DOCKER_SUBNET")
				}
				iface = ifc.Name
			}
		}
	}
	if iface == "" {
		return "", netip.Addr{}, errors.New("no host interface on DOCKER_SUBNET")
	}
	return iface, ip, nil
}
