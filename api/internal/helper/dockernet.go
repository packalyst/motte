package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// DockerNetwork is the stack's Docker network (docker-compose.yml `networks: vpn-network`), the one
// Traefik and the panel's own containers share.
const DockerNetwork = "vpn-network"

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

// ContainersAbleToForge lists the containers on DockerNetwork, running or not, other than the one at
// trusted, that could send packets with another container's address: privileged, given NET_ADMIN
// (it can take the address) or keeping NET_RAW (Docker's default; it can forge it). A rule that
// trusts trusted's source address on that network is only sound while this is empty. Any error
// means it can't be known, and the caller must treat that as unsafe.
func ContainersAbleToForge(trusted netip.Addr) ([]string, error) {
	filter := url.QueryEscape(`{"network":["` + DockerNetwork + `"]}`)
	var list []struct {
		ID              string   `json:"Id"`
		Names           []string `json:"Names"`
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := dockerGetJSON("/containers/json?all=true&filters="+filter, &list); err != nil {
		return nil, err
	}
	var out []string
	for _, c := range list {
		if ip, err := netip.ParseAddr(c.NetworkSettings.Networks[DockerNetwork].IPAddress); err == nil && ip == trusted {
			continue
		}
		var info struct {
			HostConfig struct {
				Privileged bool     `json:"Privileged"`
				CapAdd     []string `json:"CapAdd"`
				CapDrop    []string `json:"CapDrop"`
			} `json:"HostConfig"`
		}
		if err := dockerGetJSON("/containers/"+url.PathEscape(c.ID)+"/json", &info); err != nil {
			return nil, err
		}
		if h := info.HostConfig; h.Privileged || canForge(h.CapAdd, h.CapDrop) {
			name := c.ID
			if len(c.Names) > 0 {
				name = strings.TrimPrefix(c.Names[0], "/")
			}
			out = append(out, name)
		}
	}
	return out, nil
}

// canForge reports whether a container with these capability changes can send packets from an
// address that isn't its own: NET_ADMIN added, or NET_RAW (on by default) not dropped.
func canForge(add, drop []string) bool {
	has := func(caps []string, want ...string) bool {
		for _, c := range caps {
			c = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_")
			for _, w := range want {
				if c == w {
					return true
				}
			}
		}
		return false
	}
	if has(add, "ALL", "NET_ADMIN", "NET_RAW") {
		return true
	}
	return !has(drop, "ALL", "NET_RAW")
}

// dockerGetJSON GETs a Docker API path through the socket proxy and decodes a 200 response.
func dockerGetJSON(path string, v any) error {
	resp, err := DockerRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker %s: %s", strings.SplitN(path, "?", 2)[0], resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
