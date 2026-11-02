package dhcp

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"api/internal/helper"
)

// Incoming: what the internet may open to one LAN device. Nothing comes in unless the admin lists
// it here, and only:
//   - on the device's own dedicated address (egress.go: never a shared one, never the server's
//     main address, which carries the panel, SSH and the VPN);
//   - for a catalog service or a custom port (never "all other ports": there is no "everything in");
//   - from the sources listed, or from anyone when the admin says so explicitly;
//   - while the device has internet; switched off, nothing comes in (the list is kept and comes
//     back when it is switched on again, behind the same step-up).
// The port is the same outside and on the device. Moving the device to another address deletes
// its list: it belongs to the address.

// inboundAny is the source that means anyone on the internet.
const inboundAny = "any"

// Bounds on a device's list (and so on the rules it renders), refused before anything is parsed.
const (
	maxInboundEntries = 16
	maxInboundSources = 16
)

// inboundEntry is one way in: a catalog service or a custom port ("tcp:N" / "udp:N"), from
// Sources: ["any"], or public IPv4 addresses and ranges (stored as CIDRs).
type inboundEntry struct {
	Entry   string   `json:"entry"`
	Sources []string `json:"sources"`
}

// inboundRule is one entry as the rules render it: its ports, and its sources (nil = anyone).
type inboundRule struct {
	TCP, UDP []int
	Sources  []string
}

// normalizeInbound validates a device's list and returns it in a stable order: entries in catalog
// order then by port, sources sorted. Anything not understood is refused, never skipped.
func normalizeInbound(in []inboundEntry) ([]inboundEntry, error) {
	if len(in) > maxInboundEntries {
		return nil, fmt.Errorf("too many incoming entries (at most %d)", maxInboundEntries)
	}
	out := make([]inboundEntry, 0, len(in))
	for _, e := range in {
		id := strings.ToLower(strings.TrimSpace(e.Entry))
		if id == svcAll {
			return nil, fmt.Errorf("all other ports is outgoing only")
		}
		if svc, ok := catalogService(id); ok && len(svc.TCP) == 0 && len(svc.UDP) == 0 {
			return nil, fmt.Errorf("%s is outgoing only", svc.Name)
		} else if !ok {
			proto, port, ok := customPort(id)
			if !ok {
				return nil, fmt.Errorf("unknown incoming entry %q (use a listed service, or tcp:PORT / udp:PORT)", e.Entry)
			}
			if proto == "tcp" && port == 25 {
				return nil, fmt.Errorf("port 25 is opened only with the Direct mail service")
			}
		}
		if slices.ContainsFunc(out, func(x inboundEntry) bool { return x.Entry == id }) {
			return nil, fmt.Errorf("%s is listed twice", id)
		}
		src, err := normalizeSources(e.Sources)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", id, err)
		}
		out = append(out, inboundEntry{Entry: id, Sources: src})
	}
	slices.SortFunc(out, func(a, b inboundEntry) int { return entryOrder(a.Entry) - entryOrder(b.Entry) })
	return out, nil
}

// entryOrder sorts catalog services first (in catalog order), then custom ports by protocol and port.
func entryOrder(id string) int {
	if i := catalogIndex(id); i >= 0 {
		return i
	}
	proto, port, _ := customPort(id)
	if proto == "udp" {
		port += 1 << 16
	}
	return 1000 + port
}

// normalizeSources validates who may connect in: "any" alone, or public IPv4 addresses and ranges.
// A private or reserved source is refused: nothing from those arrives over the internet, and
// 0.0.0.0/0 is not a way to say anyone (that is "any", chosen on purpose).
func normalizeSources(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("say who may connect in (addresses, or anyone)")
	}
	if len(in) > maxInboundSources {
		return nil, fmt.Errorf("too many sources (at most %d)", maxInboundSources)
	}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == inboundAny {
			if len(in) != 1 {
				return nil, fmt.Errorf("anyone can't be combined with addresses")
			}
			return []string{inboundAny}, nil
		}
		p, err := sourcePrefix(s)
		if err != nil {
			return nil, err
		}
		if c := p.String(); !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out, nil
}

// sourcePrefix reads one source: a public IPv4 address (as a /32) or range.
func sourcePrefix(s string) (netip.Prefix, error) {
	p, _, err := helper.ParseIPv4(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 address or range", s)
	}
	p = p.Masked()
	if helper.OverlapsNonPublic(p) {
		return netip.Prefix{}, fmt.Errorf("%s is not a public address range", p)
	}
	return p, nil
}

// inboundRules turns a stored list into what the rules render. Anything that doesn't read back
// cleanly is skipped: a stored value never opens more than it says.
func inboundRules(list []inboundEntry) []inboundRule {
	var out []inboundRule
	for _, e := range list {
		o := portsOf(e.Entry)
		if o.All || (len(o.TCP) == 0 && len(o.UDP) == 0) {
			continue
		}
		r := inboundRule{TCP: o.TCP, UDP: o.UDP}
		if !(len(e.Sources) == 1 && e.Sources[0] == inboundAny) {
			for _, s := range e.Sources {
				if p, err := sourcePrefix(s); err == nil {
					r.Sources = append(r.Sources, p.String())
				}
			}
			if len(r.Sources) == 0 {
				continue // no valid source: nobody, not anyone
			}
		}
		out = append(out, r)
	}
	return out
}

// widensInbound reports whether going from old to new lets in anything old didn't: a new entry,
// a source not inside an old one, or anyone where old named sources (a step-up is due).
func widensInbound(old, new []inboundEntry) bool {
	for _, n := range new {
		i := slices.IndexFunc(old, func(o inboundEntry) bool { return o.Entry == n.Entry })
		if i < 0 {
			return true
		}
		if anyone(old[i].Sources) {
			continue
		}
		if anyone(n.Sources) {
			return true
		}
		for _, s := range n.Sources {
			if !sourceCovered(s, old[i].Sources) {
				return true
			}
		}
	}
	return false
}

func anyone(src []string) bool { return len(src) == 1 && src[0] == inboundAny }

// sourceCovered reports whether the range s lies inside one of the ranges in list.
func sourceCovered(s string, list []string) bool {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return false
	}
	for _, l := range list {
		if q, err := netip.ParsePrefix(l); err == nil && q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// inboundLabel names a list in audit messages and confirmations.
func inboundLabel(list []inboundEntry) string {
	if len(list) == 0 {
		return "nothing"
	}
	var parts []string
	for _, e := range list {
		from := "anyone"
		if !anyone(e.Sources) {
			from = strings.Join(e.Sources, ", ")
		}
		parts = append(parts, servicesLabel(e.Entry)+" from "+from)
	}
	return strings.Join(parts, "; ")
}

// inboundPaths names each way in, for the connection cut when one is taken away (accessOf).
func inboundPaths(rules []inboundRule) []string {
	var p []string
	for _, r := range rules {
		src := r.Sources
		if src == nil {
			src = []string{inboundAny}
		}
		for _, s := range src {
			for _, n := range r.TCP {
				p = append(p, "in tcp "+strconv.Itoa(n)+" from "+s)
			}
			for _, n := range r.UDP {
				p = append(p, "in udp "+strconv.Itoa(n)+" from "+s)
			}
		}
	}
	return p
}

// listInbound reads one device's incoming list.
func (s *Service) listInbound(clientID int64) ([]inboundEntry, error) {
	m, err := s.queryInbound(`SELECT client_id, entry, sources FROM dhcp_inbound WHERE client_id = ?`, clientID)
	return m[clientID], err
}

// networkInbound reads the incoming lists of a network's devices, by device.
func (s *Service) networkInbound(networkID int64) (map[int64][]inboundEntry, error) {
	return s.queryInbound(`SELECT i.client_id, i.entry, i.sources FROM dhcp_inbound i
		JOIN dhcp_clients c ON c.id = i.client_id WHERE c.network_id = ?`, networkID)
}

func (s *Service) queryInbound(q string, arg int64) (map[int64][]inboundEntry, error) {
	rows, err := s.db.Query(q, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]inboundEntry{}
	for rows.Next() {
		var id int64
		var e inboundEntry
		var src string
		if err := rows.Scan(&id, &e.Entry, &src); err != nil {
			return nil, err
		}
		e.Sources = strings.Split(src, ",")
		out[id] = append(out[id], e)
	}
	for id := range out {
		slices.SortFunc(out[id], func(a, b inboundEntry) int { return entryOrder(a.Entry) - entryOrder(b.Entry) })
	}
	return out, rows.Err()
}

// saveInternet stores a device's internet switch, its address, what it may reach and what may
// come in, together: an address change and the incoming list it takes away land at once.
func (s *Service) saveInternet(id int64, on bool, egress, services string, inbound []inboundEntry) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op once committed
	if _, err := tx.Exec(`UPDATE dhcp_clients SET internet=?, egress_ip=?, services=? WHERE id=?`, b2i(on), egress, services, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM dhcp_inbound WHERE client_id = ?`, id); err != nil {
		return err
	}
	for _, e := range inbound {
		if _, err := tx.Exec(`INSERT INTO dhcp_inbound (client_id, entry, sources) VALUES (?, ?, ?)`, id, e.Entry, strings.Join(e.Sources, ",")); err != nil {
			return err
		}
	}
	return tx.Commit()
}
