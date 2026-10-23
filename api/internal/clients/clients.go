// Package clients serves the All clients page: WireGuard peers, Headscale nodes, fleet machines
// and DHCP devices, normalized into one list in a single request. It owns no data — each source
// keeps its own store and page; this only reads and merges. A machine whose last report came from
// a VPN client's IP (it reports over the tunnel) is merged into that client's entry.
//
// Live updates: while anyone watches the "clients" WS channel, the list is rebuilt every few
// seconds and a bare "changed" signal is pushed when something visible changed (a client added or
// removed, online/offline, a flag). The signal carries no data; each page refetches GET
// /api/clients, which applies the caller's role and machine scope.
package clients

import (
	"crypto/sha256"
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"api/internal/adguard"
	"api/internal/dhcp"
	"api/internal/fleet"
	"api/internal/router"
	"api/internal/vpn"
	"api/internal/ws"
)

const (
	Channel       = "clients"
	watchInterval = 10 * time.Second
	keyWarnWithin = 14 * 24 * time.Hour // warn this long before a Tailscale node key expires
)

// Flag is a short state label shown on a client ("Key expired", "Not approved", …).
type Flag struct {
	Label string `json:"label"`
	Tone  string `json:"tone"`            // "destructive" | "warning"
	Icon  string `json:"icon"`            // the card shows the icon; the label is its tooltip
	Count int    `json:"count,omitempty"` // shown next to the icon (e.g. number of critical CVEs)
}

// Client is one device in the unified list.
type Client struct {
	Key      string   `json:"key"`     // stable unique id across kinds
	Kind     string   `json:"kind"`    // wireguard | tailscale | machine | lan
	Machine  bool     `json:"machine"` // a VPN client that is also an agent machine
	Name     string   `json:"name"`
	IP       string   `json:"ip"`
	Online   bool     `json:"online"`
	LastSeen string   `json:"last_seen,omitempty"`
	Meta     string   `json:"meta,omitempty"` // Tailscale user, machine OS, or LAN network
	Tx       *int64   `json:"tx,omitempty"`   // bytes sent/received (VPN clients only)
	Rx       *int64   `json:"rx,omitempty"`
	CPU      *float64 `json:"cpu,omitempty"` // busy %, memory and root-disk used % (machines only)
	Mem      *float64 `json:"mem,omitempty"`
	Disk     *float64 `json:"disk,omitempty"`
	MAC      string   `json:"mac,omitempty"` // LAN devices only
	// LAN devices: the active lease's end (unix seconds) and the network's lease length
	LeaseExpires int64    `json:"lease_expires,omitempty"`
	LeaseSecs    int      `json:"lease_secs,omitempty"`
	Flags        []Flag   `json:"flags,omitempty"`
	Tags         []string `json:"tags,omitempty"`     // Tailscale ACL tags and/or machine scoping tags
	Pending      bool     `json:"pending,omitempty"`  // LAN device waiting for approval
	Blocked      bool     `json:"blocked,omitempty"`  // LAN device blocked (no address, traffic dropped)
	Internet     *bool    `json:"internet,omitempty"` // LAN device may route out the WAN
	Gone         bool     `json:"gone,omitempty"`     // machine whose agent was uninstalled
	Open         OpenRef  `json:"open"`               // where each part of this client is managed
}

// OpenRef identifies the client on its own pages.
type OpenRef struct {
	Node      string `json:"node,omitempty"`    // Nodes page id
	MachineID string `json:"machine,omitempty"` // Machines page id
	NetworkID int64  `json:"network,omitempty"` // Networks page id
	LanID     int64  `json:"lan,omitempty"`     // DHCP client id (approve)
}

type Service struct {
	vpn   *vpn.Service
	fleet *fleet.Service
	dhcp  *dhcp.Service
}

// New wires the sources; any of them may be nil when its service is disabled.
func New(v *vpn.Service, f *fleet.Service, d *dhcp.Service) *Service {
	return &Service{vpn: v, fleet: f, dhcp: d}
}

func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"List":         s.handleList,
		"AdblockGet":   s.handleAdblockGet,
		"AdblockSet":   s.handleAdblockSet,
		"AdblockAllow": s.handleAdblockAllow,
	}
}

// GET /api/clients → {"clients":[…],"unavailable":["Machines",…]}
func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	var machines []fleet.Machine
	var mErr error
	if s.fleet != nil {
		machines, mErr = s.fleet.MachinesFor(r)
	}
	list, unavailable := s.build(machines, mErr)
	router.JSON(w, map[string]any{"clients": list, "unavailable": unavailable})
}

// build merges the sources. machines are passed in already scoped to the caller.
func (s *Service) build(machines []fleet.Machine, machinesErr error) ([]Client, []string) {
	out := []Client{}
	unavailable := []string{}

	byIP := map[string]*fleet.Machine{}
	if s.fleet == nil || machinesErr != nil {
		unavailable = append(unavailable, "Machines")
	}
	for i := range machines {
		if ip := machines[i].LastIP; ip != "" {
			byIP[ip] = &machines[i]
		}
	}
	merged := map[string]bool{}

	if s.vpn == nil {
		unavailable = append(unavailable, "VPN clients")
	} else if vcs, err := s.vpn.ListClients(); err != nil {
		unavailable = append(unavailable, "VPN clients")
	} else {
		for _, c := range vcs {
			e := fromVPN(c)
			if m := byIP[c.IP]; m != nil {
				merged[m.ID] = true
				e.Machine = true
				e.Open.MachineID = m.ID
				if e.Meta == "" && m.Summary != nil {
					e.Meta = m.Summary.OS
				}
				e.Flags = append(e.Flags, machineFlags(m)...)
				e.Tags = uniq(append(e.Tags, m.Tags...))
			}
			out = append(out, e)
		}
	}

	for i := range machines {
		m := &machines[i]
		if merged[m.ID] {
			continue
		}
		out = append(out, fromMachine(m))
	}

	if s.dhcp == nil {
		unavailable = append(unavailable, "Networks")
	} else if nets, byNet, err := s.dhcp.AllClients(); err != nil {
		unavailable = append(unavailable, "Networks")
	} else {
		for _, n := range nets {
			for _, d := range byNet[n.ID] {
				out = append(out, fromLAN(n, d))
			}
		}
	}

	for i := range out {
		if adguard.BlockingOff(out[i].Key) { // from the last known AdGuard state; no call here
			out[i].Flags = append(out[i].Flags, Flag{"Ad blocking off", "warning", "shield-off", 0})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Pending != b.Pending {
			return a.Pending
		}
		if a.Gone != b.Gone {
			return b.Gone
		}
		if a.Online != b.Online {
			return a.Online
		}
		return a.Name < b.Name
	})
	return out, unavailable
}

// vpnRaw is the subset of a VPN client's stored source data the list shows.
type vpnRaw struct {
	Online        bool     `json:"online"`
	Enabled       *bool    `json:"enabled"`
	LastHandshake string   `json:"lastHandshake"`
	LastSeen      string   `json:"lastSeen"`
	GivenName     string   `json:"givenName"`
	Name          string   `json:"name"`
	Expiry        string   `json:"expiry"`
	ForcedTags    []string `json:"forcedTags"`
	ValidTags     []string `json:"validTags"`
	User          struct {
		Name string `json:"name"`
	} `json:"user"`
}

func fromVPN(c vpn.VPNClient) Client {
	var raw vpnRaw
	_ = json.Unmarshal(c.RawData, &raw)
	tx, rx := c.TotalTx, c.TotalRx
	e := Client{IP: c.IP, Online: raw.Online, Tx: &tx, Rx: &rx}
	if c.Type == "wireguard" {
		e.Kind, e.Key, e.Name = "wireguard", "wg:"+c.ExternalID, c.Name
		e.Open.Node = "wg-" + c.ExternalID
		e.LastSeen = firstNonEmpty(raw.LastHandshake, raw.LastSeen)
		if raw.Enabled != nil && !*raw.Enabled {
			e.Flags = append(e.Flags, Flag{"Disabled", "warning", "player-pause", 0})
		}
	} else {
		e.Kind, e.Key, e.Name = "tailscale", "ts:"+c.ExternalID, firstNonEmpty(raw.GivenName, raw.Name, c.Name)
		e.Open.Node = c.ExternalID
		e.LastSeen = raw.LastSeen
		e.Meta = raw.User.Name
		e.Tags = uniq(append(raw.ForcedTags, raw.ValidTags...))
		e.Flags = append(e.Flags, keyExpiryFlags(raw.Expiry, time.Now())...)
	}
	if c.BlockInternet {
		e.Flags = append(e.Flags, Flag{"No internet", "destructive", "world-off", 0})
	}
	return e
}

// keyExpiryFlags flags a Tailscale node key that has expired (the device is cut off) or expires
// within keyWarnWithin. A zero/unparseable expiry means the key never expires.
func keyExpiryFlags(expiry string, now time.Time) []Flag {
	t, err := time.Parse(time.RFC3339, expiry)
	if err != nil || t.Year() <= 1 {
		return nil
	}
	left := t.Sub(now)
	switch {
	case left <= 0:
		return []Flag{{"Key expired", "destructive", "key-off", 0}}
	case left <= keyWarnWithin:
		days := int(math.Ceil(left.Hours() / 24))
		label := "Key expires in " + strconv.Itoa(days) + " days"
		if days == 1 {
			label = "Key expires within a day"
		}
		return []Flag{{label, "warning", "key", 0}}
	}
	return nil
}

func fromMachine(m *fleet.Machine) Client {
	e := Client{Key: "m:" + m.ID, Kind: "machine", Name: firstNonEmpty(m.Name, m.ID), IP: m.LastIP,
		Open: OpenRef{MachineID: m.ID}, Flags: machineFlags(m), Tags: m.Tags}
	e.Online = m.Online // its link to the panel is up
	e.Gone = m.Status == "uninstalled"
	if m.LastSeen != nil {
		e.LastSeen = m.LastSeen.UTC().Format(time.RFC3339)
	}
	if m.Summary != nil {
		e.Meta = m.Summary.OS
		e.CPU, e.Mem, e.Disk = &m.Summary.CPU, &m.Summary.Mem, &m.Summary.Disk
	}
	return e
}

func machineFlags(m *fleet.Machine) []Flag {
	if m.Status == "uninstalled" {
		return nil // the card itself shows it; the revocation comes with it
	}
	var f []Flag
	if m.Revoked {
		f = append(f, Flag{"Revoked", "destructive", "certificate", 0})
	}
	if s := m.Summary; s != nil {
		if s.CVECritical > 0 {
			f = append(f, Flag{strconv.Itoa(s.CVECritical) + " critical CVE", "destructive", "bug", s.CVECritical})
		}
		if s.Bans > 0 {
			f = append(f, Flag{strconv.Itoa(s.Bans) + " active bans (CrowdSec)", "destructive", "skull", s.Bans})
		}
		if s.FIM > 0 {
			f = append(f, Flag{strconv.Itoa(s.FIM) + " file changes (FIM)", "warning", "file-search", s.FIM})
		}
	}
	return f
}

func fromLAN(n dhcp.Network, d dhcp.Client) Client {
	internet := d.Internet
	if d.Blocked {
		d.LeaseExpires = 0 // its old lease may linger in the lease file, but it won't be renewed
	}
	e := Client{Key: "lan:" + strconv.FormatInt(d.ID, 10), Kind: "lan", Name: firstNonEmpty(d.Name, d.MAC), IP: d.IP,
		Online: d.Online && !d.Blocked, LastSeen: d.LastSeen, Meta: n.Iface + " · " + n.CIDR, MAC: d.MAC,
		LeaseExpires: d.LeaseExpires, LeaseSecs: n.LeaseSecs, Internet: &internet,
		Pending: !d.Approved && !d.Blocked, Blocked: d.Blocked, Open: OpenRef{NetworkID: n.ID, LanID: d.ID}}
	switch {
	case d.Blocked:
		e.Flags = []Flag{{"Blocked", "destructive", "ban", 0}}
	case !d.Approved:
		e.Flags = []Flag{{"Not approved", "warning", "user-question", 0}}
	}
	return e
}

// ---- live change signal ----------------------------------------------------------------------

var watchOnce sync.Once

// Watch starts the change notifier (idle unless the channel has subscribers). The digest covers
// what the list shows except traffic counters and last-seen times, which tick constantly.
func (s *Service) Watch() {
	watchOnce.Do(func() {
		go func() {
			var last [32]byte
			t := time.NewTicker(watchInterval)
			defer t.Stop()
			for range t.C {
				if ws.ChannelSubscriberCount(Channel) == 0 {
					last = [32]byte{}
					continue
				}
				var machines []fleet.Machine
				var err error
				if s.fleet != nil {
					machines, err = s.fleet.ListMachines()
				}
				list, _ := s.build(machines, err)
				if d := digest(list); d != last {
					if last != ([32]byte{}) {
						ws.Broadcast(Channel, map[string]string{"event": "changed"})
					}
					last = d
				}
			}
		}()
	})
}

func digest(list []Client) [32]byte {
	type key struct {
		K, Kind, Name, IP string
		On, Pend, M, Blk  bool
		Gone              bool
		Net               *bool
		F                 []Flag
		Meta              string
		T                 []string
	}
	ks := make([]key, len(list))
	for i, c := range list {
		ks[i] = key{c.Key, c.Kind, c.Name, c.IP, c.Online, c.Pending, c.Machine, c.Blocked, c.Gone, c.Internet, c.Flags, c.Meta, c.Tags}
	}
	b, _ := json.Marshal(ks)
	return sha256.Sum256(b)
}

// uniq drops repeated strings, keeping the first occurrence's order.
func uniq(v []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range v {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
