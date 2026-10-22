package adguard

// Per-client ad & tracker blocking. Blocking ON is the default: the client simply follows the
// global AdGuard settings. Turning it OFF adds an AdGuard persistent client the panel owns (named
// managedPrefix + the panel's client key) with filtering disabled and the other protections copied
// from the global settings. Turning it back on deletes that entry. Persistent clients the panel did
// not create are never changed — a client already covered by one is reported as managed elsewhere.
//
// "Allow for this client" adds a user rule  @@||domain^$client='ip'  (exception for one client),
// under a marker comment so the panel only ever touches its own rules.
// The IP always comes from the panel's own client record, never from the browser, and domains are
// validated before they are written into a rule.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

const managedPrefix = "wgpanel "

// ErrManagedElsewhere: AdGuard already has a persistent client for this address that the panel
// didn't create; change it in AdGuard instead.
var ErrManagedElsewhere = errors.New("AdGuard already has its own client entry for this address — change it in AdGuard")

// rulesMu serialises the panel's read-modify-write of AdGuard's user rules and client entries.
var rulesMu sync.Mutex

type persistentClient struct {
	Name              string   `json:"name"`
	IDs               []string `json:"ids"`
	UseGlobalSettings bool     `json:"use_global_settings"`
	FilteringEnabled  bool     `json:"filtering_enabled"`
}

// ManagedName is the AdGuard client name the panel uses for a client key.
func ManagedName(key string) string { return managedPrefix + key }

// getJSON GETs an AdGuard API path and decodes the JSON body into v.
func (s *Service) getJSON(path string, v any) error {
	resp, err := s.doRequest("GET", path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return fmt.Errorf("AdGuard authentication failed. Check credentials in Settings.")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("AdGuard API error: %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// postJSON POSTs a JSON body to an AdGuard API path; AdGuard's own message is kept on failure.
func (s *Service) postJSON(path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := s.doRequest("POST", path, newBytesReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("AdGuard: %s", strings.TrimSpace(string(msg)))
	}
	return nil
}

func service() (*Service, error) {
	if serviceInstance == nil {
		return nil, errors.New("AdGuard service not initialized")
	}
	return serviceInstance, nil
}

func (s *Service) persistentClients() ([]persistentClient, error) {
	var res struct {
		Clients []persistentClient `json:"clients"`
	}
	if err := s.getJSON("/control/clients", &res); err != nil {
		return nil, err
	}
	rememberManaged(res.Clients)
	return res.Clients, nil
}

// ---- cache of the panel's entries, so the client list can flag them without calling AdGuard ----

var (
	cacheMu      sync.RWMutex
	managedCache = map[string]bool{} // client key → blocking off
)

func rememberManaged(list []persistentClient) {
	m := map[string]bool{}
	for _, c := range list {
		if key, ok := strings.CutPrefix(c.Name, managedPrefix); ok {
			m[key] = true
		}
	}
	cacheMu.Lock()
	managedCache = m
	cacheMu.Unlock()
}

// BlockingOff reports, from the last known AdGuard state, whether the panel turned blocking off for
// a client key. Never calls AdGuard.
func BlockingOff(key string) bool {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	return managedCache[key]
}

// ---- blocking state -------------------------------------------------------------------------------

// BlockingState is what the client's Protection panel shows.
type BlockingState struct {
	Blocking         bool   `json:"blocking"`
	GlobalOff        bool   `json:"global_off"`                  // filtering is off for everyone
	ManagedElsewhere string `json:"managed_elsewhere,omitempty"` // AdGuard client entry not made by the panel
}

// keyRe is the shape of a panel client key ("wg:3", "ts:12", "lan:7"). Keys go into AdGuard
// client names and rule comments, so nothing else is accepted.
var keyRe = regexp.MustCompile(`^(wg|ts|lan):[A-Za-z0-9_-]{1,64}$`)

// ValidKey reports whether key is a client key the panel manages blocking for.
func ValidKey(key string) bool { return keyRe.MatchString(key) }

func validClient(key, ip string) error {
	if !ValidKey(key) {
		return errors.New("invalid client")
	}
	return validIP(ip)
}

func validIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return errors.New("this client has no address yet")
	}
	return nil
}

func (s *Service) globalFiltering() (bool, error) {
	var st struct {
		Enabled bool `json:"enabled"`
	}
	err := s.getJSON("/control/filtering/status", &st)
	return st.Enabled, err
}

// ClientBlocking returns the blocking state for the client with this key and address.
func ClientBlocking(key, ip string) (BlockingState, error) {
	if err := validClient(key, ip); err != nil {
		return BlockingState{}, err
	}
	s, err := service()
	if err != nil {
		return BlockingState{}, err
	}
	global, err := s.globalFiltering()
	if err != nil {
		return BlockingState{}, err
	}
	list, err := s.persistentClients()
	if err != nil {
		return BlockingState{}, err
	}
	st := BlockingState{Blocking: global, GlobalOff: !global}
	for _, c := range list {
		if c.Name == ManagedName(key) {
			st.Blocking = false
			return st, nil
		}
	}
	for _, c := range list {
		if containsID(c.IDs, ip) {
			st.ManagedElsewhere = c.Name
			if !c.UseGlobalSettings {
				st.Blocking = c.FilteringEnabled
			}
		}
	}
	return st, nil
}

func containsID(ids []string, ip string) bool {
	for _, id := range ids {
		if id == ip {
			return true
		}
	}
	return false
}

// SetClientBlocking turns blocking on (removes the panel's entry) or off (adds or updates it).
func SetClientBlocking(key, ip string, blocking bool) error {
	if err := validClient(key, ip); err != nil {
		return err
	}
	s, err := service()
	if err != nil {
		return err
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	list, err := s.persistentClients()
	if err != nil {
		return err
	}
	var ours *persistentClient
	for i, c := range list {
		if c.Name == ManagedName(key) {
			ours = &list[i]
		} else if containsID(c.IDs, ip) {
			return ErrManagedElsewhere
		}
	}
	if blocking {
		if ours == nil {
			return nil
		}
		err = s.postJSON("/control/clients/delete", map[string]string{"name": ours.Name})
	} else {
		var data map[string]any
		if data, err = s.unfilteredClient(key, ip); err != nil {
			return err
		}
		if ours == nil {
			err = s.postJSON("/control/clients/add", data)
		} else {
			err = s.postJSON("/control/clients/update", map[string]any{"name": ours.Name, "data": data})
		}
	}
	if err == nil {
		_, err = s.persistentClients() // refresh the cache
	}
	return err
}

// unfilteredClient builds the panel's entry: filtering off, every other protection as configured
// globally (a persistent client with its own settings would otherwise turn them all off).
func (s *Service) unfilteredClient(key, ip string) (map[string]any, error) {
	var sb, pc struct {
		Enabled bool `json:"enabled"`
	}
	var safeSearch map[string]any
	if err := s.getJSON("/control/safebrowsing/status", &sb); err != nil {
		return nil, err
	}
	if err := s.getJSON("/control/parental/status", &pc); err != nil {
		return nil, err
	}
	if err := s.getJSON("/control/safesearch/status", &safeSearch); err != nil {
		return nil, err
	}
	return map[string]any{
		"name":                        ManagedName(key),
		"ids":                         []string{ip},
		"use_global_settings":         false,
		"filtering_enabled":           false,
		"safebrowsing_enabled":        sb.Enabled,
		"parental_enabled":            pc.Enabled,
		"safe_search":                 safeSearch,
		"use_global_blocked_services": true,
	}, nil
}

// ---- recently blocked -------------------------------------------------------------------------------

// BlockedQuery is one blocked lookup from the query log.
type BlockedQuery struct {
	Domain string `json:"domain"`
	Time   string `json:"time"`
	Reason string `json:"reason"`
	Rule   string `json:"rule,omitempty"`
}

// RecentBlocked returns up to n of the client's most recent blocked lookups (newest first, one per
// domain).
func RecentBlocked(ip string, n int) ([]BlockedQuery, error) {
	if err := validIP(ip); err != nil {
		return nil, err
	}
	s, err := service()
	if err != nil {
		return nil, err
	}
	q := url.Values{"search": {ip}, "response_status": {"blocked"}, "limit": {"300"}}
	var res struct {
		Data []struct {
			Client   string `json:"client"`
			Time     string `json:"time"`
			Reason   string `json:"reason"`
			Question struct {
				Name string `json:"name"`
			} `json:"question"`
			Rules []struct {
				Text string `json:"text"`
			} `json:"rules"`
		} `json:"data"`
	}
	if err := s.getJSON("/control/querylog?"+q.Encode(), &res); err != nil {
		return nil, err
	}
	out := []BlockedQuery{}
	seen := map[string]bool{}
	for _, e := range res.Data {
		// search is a substring match (10.8.0.5 also finds 10.8.0.50) — keep exact matches only
		if e.Client != ip || seen[e.Question.Name] {
			continue
		}
		seen[e.Question.Name] = true
		b := BlockedQuery{Domain: e.Question.Name, Time: e.Time, Reason: e.Reason}
		if len(e.Rules) > 0 {
			b.Rule = e.Rules[0].Text
		}
		out = append(out, b)
		if len(out) == n {
			break
		}
	}
	return out, nil
}

// ---- per-client allow rules ---------------------------------------------------------------------------

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeDomain lower-cases a domain and checks it is a plain hostname (letters, digits, hyphens
// and dots only), so it can never smuggle rule syntax into AdGuard.
func NormalizeDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if len(d) > 253 || !domainRe.MatchString(d) {
		return "", errors.New("not a valid domain name")
	}
	return d, nil
}

// Each panel allow rule is written as two lines: a marker comment naming the client, then the rule.
// Only lines under a panel marker are ever read, changed or removed — rules written by hand in
// AdGuard are left alone.
const allowMarker = "! wgpanel allow "

func allowRule(domain, ip string) string {
	return "@@||" + domain + "^$client='" + ip + "'"
}

// parseAllowRule returns the domain and IP of a rule in the panel's allow format.
func parseAllowRule(rule string) (domain, ip string, ok bool) {
	rest, ok := strings.CutPrefix(rule, "@@||")
	if !ok {
		return "", "", false
	}
	domain, rest, ok = strings.Cut(rest, "^$client='")
	if !ok || !strings.HasSuffix(rest, "'") {
		return "", "", false
	}
	ip = strings.TrimSuffix(rest, "'")
	if _, err := NormalizeDomain(domain); err != nil || net.ParseIP(ip) == nil {
		return "", "", false
	}
	return domain, ip, true
}

// panelRule is one marker + rule pair found in the user rules.
type panelRule struct {
	key, domain, ip string
	at              int // index of the marker line
}

// panelRules finds the panel's allow rules (marker line directly followed by a valid rule).
func panelRules(rules []string) []panelRule {
	var out []panelRule
	for i := 0; i+1 < len(rules); i++ {
		key, ok := strings.CutPrefix(rules[i], allowMarker)
		if !ok {
			continue
		}
		if d, ip, ok := parseAllowRule(rules[i+1]); ok {
			out = append(out, panelRule{key: key, domain: d, ip: ip, at: i})
			i++
		}
	}
	return out
}

// withoutPairs drops the marker + rule lines of the given panel rules.
func withoutPairs(rules []string, drop []panelRule) []string {
	skip := map[int]bool{}
	for _, p := range drop {
		skip[p.at], skip[p.at+1] = true, true
	}
	out := make([]string, 0, len(rules))
	for i, r := range rules {
		if !skip[i] {
			out = append(out, r)
		}
	}
	return out
}

func (s *Service) userRules() ([]string, error) {
	var st struct {
		UserRules []string `json:"user_rules"`
	}
	err := s.getJSON("/control/filtering/status", &st)
	return st.UserRules, err
}

// AllowedForClient lists the domains the panel allowed for this client at its current address.
func AllowedForClient(key, ip string) ([]string, error) {
	if err := validClient(key, ip); err != nil {
		return nil, err
	}
	s, err := service()
	if err != nil {
		return nil, err
	}
	rules, err := s.userRules()
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, p := range panelRules(rules) {
		if p.key == key && p.ip == ip {
			out = append(out, p.domain)
		}
	}
	return out, nil
}

// SetAllowed adds (allow=true) or removes the panel's allow rule for domain on one client.
func SetAllowed(key, ip, domain string, allow bool) error {
	if err := validClient(key, ip); err != nil {
		return err
	}
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return err
	}
	return editRules(func(rules []string) []string {
		var drop []panelRule
		for _, p := range panelRules(rules) {
			if p.key == key && p.domain == domain {
				drop = append(drop, p)
			}
		}
		out := withoutPairs(rules, drop)
		if allow {
			out = append(out, allowMarker+key, allowRule(domain, ip))
		}
		return out
	})
}

// editRules applies fn to AdGuard's user rules and saves them when they changed.
func editRules(fn func([]string) []string) error {
	s, err := service()
	if err != nil {
		return err
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rules, err := s.userRules()
	if err != nil {
		return err
	}
	next := fn(rules)
	if strings.Join(next, "\n") == strings.Join(rules, "\n") {
		return nil
	}
	return s.postJSON("/control/filtering/set_rules", map[string]any{"rules": next})
}

// ---- cleanup -------------------------------------------------------------------------------------------

// SyncManaged makes the panel's AdGuard entries match the current clients (key → IP): entries for
// clients that are gone are removed, and a client whose address changed is moved to the new one.
// The panel's allow rules for clients that are gone, or that moved address, are removed too, so a
// deleted client's exceptions never carry over to a device that later gets the same address.
func SyncManaged(current map[string]string) error {
	s, err := service()
	if err != nil {
		return err
	}
	rulesMu.Lock()
	list, err := s.persistentClients()
	if err == nil {
		for _, c := range list {
			key, ok := strings.CutPrefix(c.Name, managedPrefix)
			if !ok {
				continue
			}
			ip, exists := current[key]
			switch {
			case !exists:
				err = errors.Join(err, s.postJSON("/control/clients/delete", map[string]string{"name": c.Name}))
			case ip != "" && !containsID(c.IDs, ip):
				data, derr := s.unfilteredClient(key, ip)
				if derr == nil {
					derr = s.postJSON("/control/clients/update", map[string]any{"name": c.Name, "data": data})
				}
				err = errors.Join(err, derr)
			}
		}
		if _, rerr := s.persistentClients(); rerr != nil {
			err = errors.Join(err, rerr)
		}
	}
	rulesMu.Unlock()
	if err != nil {
		return err
	}
	return editRules(func(rules []string) []string {
		var drop []panelRule
		for _, p := range panelRules(rules) {
			if ip, ok := current[p.key]; !ok || (ip != "" && ip != p.ip) {
				drop = append(drop, p)
			}
		}
		return withoutPairs(rules, drop)
	})
}
