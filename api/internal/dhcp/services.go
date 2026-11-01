package dhcp

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// What a LAN device with internet may reach out there. Nothing is allowed unless it is listed: a
// device gets the default services, and an admin opens more per network (its devices' default)
// or per device. This catalog is the one place services are named; the UI reads it from the API.

// service is a named set of destination ports a device may use on the internet.
type service struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	TCP  []int  `json:"tcp,omitempty"`
	UDP  []int  `json:"udp,omitempty"`
	Note string `json:"note,omitempty"`
}

const (
	svcAll  = "all"  // every port, except direct mail unless svcSMTP is given too
	svcSMTP = "smtp" // direct mail (TCP 25): only for a real mail server
)

var serviceCatalog = []service{
	{ID: "web", Name: "Web", TCP: []int{80, 443}, UDP: []int{443}},
	{ID: "time", Name: "Time", UDP: []int{123}},
	{ID: "email", Name: "Email", TCP: []int{587, 465, 993, 995}, Note: "sending through a provider and reading mail"},
	{ID: "ssh", Name: "SSH", TCP: []int{22}},
	{ID: svcAll, Name: "Everything", Note: "every port except direct mail"},
	{ID: svcSMTP, Name: "Direct mail", TCP: []int{25}, Note: "only for a mail server"},
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
// only through the Direct mail service, so opening it is always a deliberate choice.
func normalizeServices(v string) (string, error) {
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
	if len(ids)+len(ports) > maxServiceEntries {
		return "", fmt.Errorf("too many services (at most %d)", maxServiceEntries)
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

// outPorts is what a list lets a device reach: all ports (with or without direct mail), or the
// listed TCP and UDP ports. Anything unrecognized grants nothing.
type outPorts struct {
	All, SMTP bool
	TCP, UDP  []int
}

func portsOf(list string) outPorts {
	var o outPorts
	add := func(to *[]int, ports ...int) {
		for _, p := range ports {
			if p > 0 && p <= 65535 && !slices.Contains(*to, p) {
				*to = append(*to, p)
			}
		}
	}
	for _, tok := range strings.Split(list, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch tok {
		case svcAll:
			o.All = true
			continue
		case svcSMTP:
			o.SMTP = true
		}
		if s, ok := catalogService(tok); ok {
			add(&o.TCP, s.TCP...)
			add(&o.UDP, s.UDP...)
			continue
		}
		if proto, port, ok := customPort(tok); ok && !(proto == "tcp" && port == 25) {
			if proto == "tcp" {
				add(&o.TCP, port)
			} else {
				add(&o.UDP, port)
			}
		}
	}
	slices.Sort(o.TCP)
	slices.Sort(o.UDP)
	return o
}

// any reports whether the list opens anything at all.
func (o outPorts) any() bool { return o.All || len(o.TCP) > 0 || len(o.UDP) > 0 }

// paths names each way out, for the connection cut on lost access (accessOf).
func (o outPorts) paths() []string {
	var p []string
	if o.All {
		p = append(p, "out all")
	}
	if o.SMTP {
		p = append(p, "out smtp")
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
	if n.SMTP && !o.SMTP {
		return true
	}
	if o.All {
		return false
	}
	if n.All {
		return true
	}
	for _, p := range n.TCP {
		if !slices.Contains(o.TCP, p) {
			return true
		}
	}
	for _, p := range n.UDP {
		if !slices.Contains(o.UDP, p) {
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
