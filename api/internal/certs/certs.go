// Package certs gathers every certificate the panel depends on (the websites' Let's Encrypt
// certificates, the fleet CA, the agent listener's certificate and each machine's client
// certificate) for the Certificates page, and warns admins before any of them expires.
package certs

import (
	"context"
	"database/sql"
	"net"
	"strings"
	"sync"
	"time"

	"api/internal/fleet"
	"api/internal/helper"
	"api/internal/settings"
	"api/internal/traefik"
)

const day = 24 * time.Hour

// Website is one Let's Encrypt certificate Traefik holds, or a panel domain that has none yet.
type Website struct {
	traefik.CertificateInfo
	Role    string `json:"role,omitempty"`    // "panel" | "proxy" for the panel's own domains
	Problem string `json:"problem,omitempty"` // why it can't be issued or renewed, when known
}

// Overview is everything the Certificates page shows. Fleet is nil when the fleet is unavailable.
type Overview struct {
	Websites  []Website         `json:"websites"`
	Fleet     *fleet.CertStatus `json:"fleet"`
	Due       map[string]int    `json:"due"`       // certificate key → warning step reached (0 = expired)
	Attention int               `json:"attention"` // how many need looking at
}

// Service reads the certificates and warns about them. fleet may be nil.
type Service struct {
	db    *sql.DB
	fleet *fleet.Service
	warn  func(t tracked, level int) // sends one warning (warnAdmins; tests swap it)
}

func New(db *sql.DB, fl *fleet.Service) (*Service, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS cert_alerts (
		cert_key  TEXT PRIMARY KEY,
		not_after TEXT NOT NULL,
		level     INTEGER NOT NULL
	)`)
	if err != nil {
		return nil, err
	}
	s := &Service{db: db, fleet: fl}
	s.warn = s.warnAdmins
	return s, nil
}

// tracked is one certificate the expiry check follows.
type tracked struct {
	key      string // stable id; a renewed certificate keeps it, with a new notAfter
	name     string // what the warning calls it
	action   string // what to do about it
	url      string // where the warning links to
	notAfter time.Time
	levels   []int // days-left steps it warns at, highest first; 0 = expired
}

// Overview collects every certificate, with what needs attention.
func (s *Service) Overview(ctx context.Context) Overview {
	o := Overview{Websites: websites(ctx)}
	if s.fleet != nil {
		if st, err := s.fleet.CertStatus(); err == nil {
			o.Fleet = &st
		}
	}
	o.Due = map[string]int{}
	now := time.Now()
	for _, t := range trackedList(o) {
		if l, due := currentLevel(t, now); due {
			o.Due[t.key] = l
		}
	}
	o.Attention = len(o.Due)
	for _, w := range o.Websites {
		if _, due := o.Due["web:"+w.Domain]; w.Problem != "" && !due {
			o.Attention++
		}
	}
	return o
}

// websites lists Traefik's certificates plus the panel's own domains that have none, flagging any
// Let's Encrypt can't reach to renew.
func websites(ctx context.Context) []Website {
	certs, _ := traefik.GetCertificates()
	out := make([]Website, 0, len(certs)+2)
	have := map[string]bool{}
	roles := map[string]string{}
	if d := helper.GetEnvOptional("SSL_DOMAIN", ""); d != "" {
		roles[d] = "panel"
	}
	if d := helper.GetEnvOptional("PROXY_DOMAIN", ""); d != "" {
		roles[d] = "proxy"
	}
	for _, c := range certs {
		have[c.Domain] = true
		out = append(out, Website{CertificateInfo: c, Role: roles[c.Domain]})
	}
	for d, role := range roles {
		if !have[d] {
			out = append(out, Website{CertificateInfo: traefik.CertificateInfo{Domain: d, Status: "missing", Resolver: "letsencrypt"}, Role: role})
		}
	}
	cfOnly := settings.GetWebCloudflareOnly()
	var wg sync.WaitGroup
	for i := range out { // each lookup waits up to 3s: run them side by side
		wg.Add(1)
		go func(w *Website) {
			defer wg.Done()
			w.Problem = renewProblem(ctx, w.Domain, w.Resolver, cfOnly)
			if w.Problem == "" && w.Status == "missing" {
				w.Problem = "No certificate yet. Traefik requests one on the first visit; check that the domain points to this server."
			}
		}(&out[i])
	}
	wg.Wait()
	return out
}

// renewProblem explains why Let's Encrypt can't check a domain over HTTP: with Cloudflare-only on,
// ports 80/443 only take Cloudflare's addresses, so a domain that points straight at this server
// (not proxied by Cloudflare) can't be reached by Let's Encrypt's check. DNS-challenge certificates
// don't need the ports. Unknown (lookup failed) is not reported as a problem.
func renewProblem(ctx context.Context, domain, resolver string, cfOnly bool) string {
	if !cfOnly || strings.Contains(resolver, "dns") || strings.HasPrefix(domain, "*.") {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if !helper.IsCloudflareIP(a.IP.String()) {
			return "Can't renew: Cloudflare-only is on, and this domain isn't proxied by Cloudflare, so Let's Encrypt can't reach it. Switch it to the DNS check or turn Cloudflare-only off."
		}
	}
	return ""
}

// autoLevels are the warning steps for a certificate that renews itself: it should have been
// renewed long before, so reaching one means renewal is failing. Only steps below half the
// renewal window are kept, so a normal renewal never warns.
var autoLevels = []int{14, 7, 3, 1, 0}

// caLevels are the warning steps for the fleet CA, which is replaced by hand.
var caLevels = []int{365, 90, 30, 14, 7, 3, 1, 0}

// renewingLevels keeps the autoLevels below half of the window in which a certificate of this
// lifetime renews (the last third of its life).
func renewingLevels(lifetime time.Duration) []int {
	limit := int(lifetime / 3 / 2 / day)
	out := []int{}
	for _, l := range autoLevels {
		if l < limit || l == 0 {
			out = append(out, l)
		}
	}
	return out
}

func trackedWebsite(w Website) tracked {
	return tracked{
		key: "web:" + w.Domain, name: "Website certificate for " + w.Domain, url: "/settings#s=certificates",
		action:   "Traefik should have renewed it by now: check that the domain reaches this server and Traefik's log.",
		notAfter: w.NotAfter, levels: renewingLevels(w.NotAfter.Sub(w.NotBefore)),
	}
}

// trackedList lists every certificate the expiry check follows.
func trackedList(o Overview) []tracked {
	var out []tracked
	for _, w := range o.Websites {
		if !w.NotAfter.IsZero() {
			out = append(out, trackedWebsite(w))
		}
	}
	if f := o.Fleet; f != nil {
		out = append(out, tracked{
			key: "fleet-ca", name: "Fleet CA", url: "/settings#s=certificates", notAfter: f.CA.NotAfter, levels: caLevels,
			action: "Every agent stops trusting the panel when it expires.",
		})
		if f.Listener != nil {
			out = append(out, tracked{
				key: "fleet-listener", name: "Agent listener certificate", url: "/settings#s=certificates",
				action:   "It should renew by itself: use Renew now on the Certificates page.",
				notAfter: f.Listener.NotAfter, levels: renewingLevels(f.Listener.NotAfter.Sub(f.Listener.NotBefore)),
			})
		}
		for _, a := range f.Agents {
			out = append(out, tracked{
				key: "agent:" + a.MachineID, name: "Agent certificate of " + a.Name, url: "/clients#m=" + a.MachineID,
				action:   "The agent hasn't renewed it, usually because the machine is offline. Once it expires the machine must be re-enrolled.",
				notAfter: a.NotAfter, levels: renewingLevels(time.Duration(f.AgentLifetimeDays) * day),
			})
		}
	}
	return out
}

// currentLevel is the lowest warning step a certificate has reached (due=false: none yet).
func currentLevel(t tracked, now time.Time) (level int, due bool) {
	left := t.notAfter.Sub(now)
	for _, l := range t.levels {
		if left <= time.Duration(l)*day {
			level, due = l, true
		}
	}
	return level, due
}
