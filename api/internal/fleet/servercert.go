package fleet

import (
	"crypto/tls"
	"log"
	"slices"
	"strings"
	"sync"
	"time"
)

// The fleet listener's own server certificate: what agents check against the panel CA they pinned.
// It's minted on demand and held in memory, then replaced before it expires and as soon as the
// host's addresses or domain change, so neither a long-running API nor a new IP strands the agents.

const (
	serverCertTTL     = 90 * 24 * time.Hour
	serverCertRenewAt = 30 * 24 * time.Hour // replace it once this little is left
	serverCertRecheck = 10 * time.Minute    // how often a handshake re-reads the host's addresses
)

type serverCertCache struct {
	mu      sync.Mutex
	cert    *tls.Certificate
	hosts   []string  // the names and IPs it was made for, sorted
	checked time.Time // when hosts were last compared with the live ones
}

// serverCertificate is the listener's tls.Config.GetCertificate.
func (s *Service) serverCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := &s.srvCert
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	stale := c.cert == nil || c.cert.Leaf.NotAfter.Sub(now) < serverCertRenewAt
	var hosts []string
	if stale || now.Sub(c.checked) >= serverCertRecheck {
		hosts = detectHostSANs(s.sslDomain)
		slices.Sort(hosts)
		c.checked = now
		stale = stale || !slices.Equal(hosts, c.hosts)
	}
	if !stale {
		return c.cert, nil
	}
	cert, err := s.ca.ServerCertificate(hosts, serverCertTTL)
	if err != nil {
		if c.cert != nil && now.Before(c.cert.Leaf.NotAfter) {
			log.Printf("fleet: could not renew the listener certificate, keeping the current one: %v", err)
			return c.cert, nil
		}
		return nil, err
	}
	c.cert, c.hosts = &cert, hosts
	log.Printf("fleet: listener certificate issued for %s, valid until %s", strings.Join(hosts, ", "), cert.Leaf.NotAfter.UTC().Format(time.DateOnly))
	return c.cert, nil
}
