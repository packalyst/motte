package dhcp

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// What a LAN device with internet may reach out there, in one of two modes:
//   - only the listed services and custom ports (the default: web and time);
//   - "all": every port except those of the catalog services left out — a service is then a
//     guarded port group that stays shut until it is ticked (direct mail and outside DNS included).
// An admin sets it per network (its devices' default) or per device. This catalog is the one
// place services are named; the UI reads it from the API.

// service is a named set of destination ports a device may use on the internet; ICMP is ping
// (an echo request out, its reply back), outgoing only.
type service struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	TCP  []int  `json:"tcp,omitempty"`
	UDP  []int  `json:"udp,omitempty"`
	ICMP bool   `json:"icmp,omitempty"`
	Note string `json:"note,omitempty"`
}

// svcAll switches a list to "every port except the services not in it".
const svcAll = "all"

var serviceCatalog = []service{
	{ID: "web", Name: "Web", TCP: []int{80, 443}, UDP: []int{443}},
	{ID: "time", Name: "Time", UDP: []int{123}},
	{ID: "email", Name: "Email", TCP: []int{587, 465, 993, 995}, Note: "sending through a provider and reading mail"},
	{ID: "ssh", Name: "SSH", TCP: []int{22}},
	{ID: "ping", Name: "Ping", ICMP: true, Note: "pinging hosts on the internet"},
	// Outside DNS: plain (53), over TLS (TCP 853) and over QUIC (UDP 853). Shut, a device's plain
	// lookups are answered by AdGuard wherever they were aimed, and the encrypted ones can't go out;
	// DNS over HTTPS rides on 443 and no port can tell it apart.
	{ID: "dns", Name: "Outside DNS", TCP: []int{53, 853}, UDP: []int{53, 853}, Note: "other DNS servers, skipping ad blocking"},
	{ID: "smtp", Name: "Direct mail", TCP: []int{25}, Note: "only for a mail server"},
	{ID: svcAll, Name: "All other ports", Note: "every port except the services not ticked"},
}

// defaultServices is what a device gets when neither it nor its network says otherwise.
var defaultServices = []string{"web", "time"}

// maxServiceEntries bounds a list (and so the rules it renders).
const maxServiceEntries = 64

func catalogService(id string) (service, bool) {
	for _, s := range serviceCatalog {
		if s.ID == id {
			return s, true
		}
	}
	return service{}, false
}

// servicesInfo is what the UI needs to show and pick services.
func servicesInfo() map[string]any {
	return map[string]any{"catalog": serviceCatalog, "default": strings.Join(defaultServices, ",")}
}

// normalizeServices validates a stored or submitted list ("web,time,tcp:8883") and returns it in
// a stable order; "" stays "" (inherit). Custom ports are "tcp:N" or "udp:N", 1-65535; port 25
// only through the Direct mail service, so opening it is always a deliberate choice. With "all",
// custom ports mean nothing (every port not guarded by a service is open) and are dropped.
// An over-long list is refused before any entry is read, so its size costs nothing.
func normalizeServices(v string) (string, error) {
	if strings.Count(v, ",") >= maxServiceEntries {
		return "", fmt.Errorf("too many services (at most %d)", maxServiceEntries)
	}
	var ids, ports []string
	for _, tok := range strings.Split(v, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch {
		case tok == "":
			continue
		case slices.Contains(ids, tok) || slices.Contains(ports, tok):
			continue
		}
		if _, ok := catalogService(tok); ok {
			ids = append(ids, tok)
			continue
		}
		proto, port, ok := customPort(tok)
		if !ok {
			return "", fmt.Errorf("unknown service %q (use a listed service, or tcp:PORT / udp:PORT)", tok)
		}
		if proto == "tcp" && port == 25 {
			return "", fmt.Errorf("port 25 is opened only with the Direct mail service")
		}
		ports = append(ports, tok)
	}
	if slices.Contains(ids, svcAll) {
		ports = nil
	}
	slices.SortFunc(ids, func(a, b string) int { return catalogIndex(a) - catalogIndex(b) })
	slices.SortFunc(ports, func(a, b string) int {
		pa, na, _ := customPort(a)
		pb, nb, _ := customPort(b)
		if pa != pb {
			return strings.Compare(pa, pb)
		}
		return na - nb
	})
	return strings.Join(append(ids, ports...), ","), nil
}

func catalogIndex(id string) int {
	return slices.IndexFunc(serviceCatalog, func(s service) bool { return s.ID == id })
}

// customPort reads "tcp:N" / "udp:N".
func customPort(tok string) (string, int, bool) {
	proto, num, ok := strings.Cut(tok, ":")
	if !ok || (proto != "tcp" && proto != "udp") {
		return "", 0, false
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != num {
		return "", 0, false
	}
	return proto, n, true
}

// effectiveServices is the list a device's internet uses: its own, else its network's, else the
// default.
func effectiveServices(n *Network, c *Client) string {
	switch {
	case c != nil && c.Services != "":
		return c.Services
	case n != nil && n.Services != "":
		return n.Services
	}
	return strings.Join(defaultServices, ",")
}

// outPorts is what a list lets a device reach. Without All: only TCP and UDP. With All: every
// port except BlockTCP and BlockUDP, the ports of the services left out (TCP and UDP then hold
// the ticked services' ports). Anything unrecognized grants nothing.
type outPorts struct {
	All                bool
	TCP, UDP           []int
	BlockTCP, BlockUDP []int
	ICMP, BlockICMP    bool // ping out allowed; with All, ping guarded (Ping not ticked)
}

func addPorts(to *[]int, ports ...int) {
	for _, p := range ports {
		if p > 0 && p <= 65535 && !slices.Contains(*to, p) {
			*to = append(*to, p)
		}
	}
}

func portsOf(list string) outPorts {
	var o outPorts
	picked := map[string]bool{}
	for _, tok := range strings.Split(list, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == svcAll {
			o.All = true
			continue
		}
		if s, ok := catalogService(tok); ok {
			picked[tok] = true
			addPorts(&o.TCP, s.TCP...)
			addPorts(&o.UDP, s.UDP...)
			o.ICMP = o.ICMP || s.ICMP
			continue
		}
		if proto, port, ok := customPort(tok); ok && !(proto == "tcp" && port == 25) {
			if proto == "tcp" {
				addPorts(&o.TCP, port)
			} else {
				addPorts(&o.UDP, port)
			}
		}
	}
	if o.All {
		for _, s := range serviceCatalog {
			if picked[s.ID] {
				continue
			}
			for _, p := range s.TCP {
				if !slices.Contains(o.TCP, p) {
					addPorts(&o.BlockTCP, p)
				}
			}
			for _, p := range s.UDP {
				if !slices.Contains(o.UDP, p) {
					addPorts(&o.BlockUDP, p)
				}
			}
			o.BlockICMP = o.BlockICMP || (s.ICMP && !o.ICMP)
		}
	}
	for _, l := range [][]int{o.TCP, o.UDP, o.BlockTCP, o.BlockUDP} {
		slices.Sort(l)
	}
	return o
}

// opens reports whether the list lets a device reach port p over proto ("tcp" or "udp").
func (o outPorts) opens(proto string, p int) bool {
	allowed, blocked := o.TCP, o.BlockTCP
	if proto == "udp" {
		allowed, blocked = o.UDP, o.BlockUDP
	}
	if o.All {
		return !slices.Contains(blocked, p)
	}
	return slices.Contains(allowed, p)
}

// any reports whether the list opens anything at all.
func (o outPorts) any() bool { return o.All || o.ICMP || len(o.TCP) > 0 || len(o.UDP) > 0 }

// pings reports whether the list lets ping out.
func (o outPorts) pings() bool { return o.ICMP || (o.All && !o.BlockICMP) }

// paths names each way out, for the connection cut on lost access (accessOf).
func (o outPorts) paths() []string {
	var p []string
	if o.All {
		p = append(p, "out all")
	}
	if o.ICMP {
		p = append(p, "out ping")
	}
	for _, n := range o.TCP {
		p = append(p, "out tcp "+strconv.Itoa(n))
	}
	for _, n := range o.UDP {
		p = append(p, "out udp "+strconv.Itoa(n))
	}
	return p
}

// widens reports whether going from old to new opens anything old didn't (a step-up is due).
func widens(old, new string) bool {
	o, n := portsOf(old), portsOf(new)
	if n.pings() && !o.pings() {
		return true
	}
	if n.All {
		if !o.All {
			return true
		}
		// Both open every port but some: new opens more if it guards fewer of old's.
		for _, p := range o.BlockTCP {
			if n.opens("tcp", p) {
				return true
			}
		}
		for _, p := range o.BlockUDP {
			if n.opens("udp", p) {
				return true
			}
		}
		return false
	}
	for _, p := range n.TCP {
		if !o.opens("tcp", p) {
			return true
		}
	}
	for _, p := range n.UDP {
		if !o.opens("udp", p) {
			return true
		}
	}
	return false
}

// servicesLabel names a list in audit messages.
func servicesLabel(list string) string {
	var names []string
	for _, tok := range strings.Split(list, ",") {
		if s, ok := catalogService(tok); ok {
			names = append(names, s.Name)
		} else if tok != "" {
			names = append(names, strings.Replace(tok, ":", " ", 1))
		}
	}
	return strings.Join(names, ", ")
}
