package sentinel

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// GateConfig closes plain HTTP to everyone but the sources the panel lists at ListURL, while
// Let's Encrypt still reaches its HTTP challenge. The panel answers "off" (everyone may: the
// gate does nothing) or "on" followed by one CIDR per line. The check is on the address that
// connected to Traefik, never on forwarded headers: those name the visitor behind Cloudflare,
// and the point is to admit Cloudflare itself.
//
// A request for an ACME challenge token always passes. Any other request from a source not
// listed is dropped silently (connection closed, no response), and its address is reported to
// ReportURL so the panel's jail can ban repeat offenders. Until the list has been fetched once,
// every non-challenge request is dropped; after that a failed fetch keeps the last list.
type GateConfig struct {
	ListURL   string `json:"listUrl,omitempty"`
	CacheTTL  int    `json:"cacheTTL,omitempty"`
	ReportURL string `json:"reportUrl,omitempty"`
}

// acmeChallengeRe matches an ACME HTTP-01 challenge path: the fixed prefix and a base64url
// token, nothing else (no further segments, no dots), so it can't be used to reach anything
// but the challenge answer.
var acmeChallengeRe = regexp.MustCompile(`^/\.well-known/acme-challenge/[A-Za-z0-9_-]+$`)

const (
	gateReportInterval = 10 * time.Second
	maxGateReportIPs   = 1024 // distinct addresses held between reports; more are not reported
	maxGateReportCount = 10   // drops reported per address per report
)

// gateList is the parsed panel answer.
type gateList struct {
	on      bool
	sources *ipDenySet
}

// parseGateList reads "off", or "on" and the allowed CIDRs. Anything else is not a valid answer
// (nil), so the last good list stays in use.
func parseGateList(body []byte) interface{} {
	text := strings.TrimSpace(string(body))
	first, rest := text, ""
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		first, rest = text[:i], text[i+1:]
	}
	switch strings.TrimSpace(first) {
	case "off":
		return &gateList{}
	case "on":
		return &gateList{on: true, sources: parseDenyList([]byte(rest)).(*ipDenySet)}
	}
	return nil
}

// gate holds the list cache and the drops waiting to be reported.
type gate struct {
	list      *remoteCache
	reportURL string

	mu      sync.Mutex
	drops   map[string]int
	pending bool // a flush is scheduled
}

func newGate(c *GateConfig) *gate {
	if c == nil || c.ListURL == "" {
		return nil
	}
	return &gate{list: newCache(c.ListURL, c.CacheTTL), reportURL: c.ReportURL, drops: map[string]int{}}
}

// peerIP is the address that connected to Traefik.
func peerIP(req *http.Request) net.IP {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	return net.ParseIP(host)
}

// admits reports whether req may go on.
func (g *gate) admits(req *http.Request) bool {
	if acmeChallengeRe.MatchString(req.URL.Path) {
		return true
	}
	l, ok := g.list.fetch(parseGateList).(*gateList)
	if !ok {
		return false // never fetched: closed
	}
	if !l.on {
		return true
	}
	ip := peerIP(req)
	return ip != nil && l.sources.contains(ip)
}

// recordDrop notes a dropped address; the batch goes to the panel gateReportInterval after the
// first drop in it ("ip count" per line). Bounded: at most maxGateReportIPs addresses wait, each
// counted up to maxGateReportCount.
func (g *gate) recordDrop(ip net.IP) {
	if g.reportURL == "" || ip == nil {
		return
	}
	key := ip.String()
	g.mu.Lock()
	defer g.mu.Unlock()
	n, seen := g.drops[key]
	if !seen && len(g.drops) >= maxGateReportIPs {
		return
	}
	if n < maxGateReportCount {
		g.drops[key] = n + 1
	}
	if !g.pending {
		g.pending = true
		time.AfterFunc(gateReportInterval, g.flush)
	}
}

// flush sends the waiting drops to the panel. Best effort: a failed send is not retried.
func (g *gate) flush() {
	g.mu.Lock()
	batch := g.drops
	g.drops = map[string]int{}
	g.pending = false
	g.mu.Unlock()

	var sb strings.Builder
	for addr, n := range batch {
		sb.WriteString(fmt.Sprintf("%s %d\n", addr, n))
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(g.reportURL, "text/plain", strings.NewReader(sb.String()))
	if err == nil {
		resp.Body.Close()
	}
}
