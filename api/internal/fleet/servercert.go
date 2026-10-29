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
	return s.listenerCert(false)
}

// RenewListenerCert replaces the listener certificate now ("Renew now"). The current one keeps
// being served if making the new one fails.
func (s *Service) RenewListenerCert() error {
	_, err := s.listenerCert(true)
	return err
}

// listenerCert returns the current listener certificate, making a new one first when forced, when
// it's close to expiry, or when the host's addresses or domain changed.
func (s *Service) listenerCert(force bool) (*tls.Certificate, error) {
	c := &s.srvCert
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	ca := s.CA()
	stale := force || c.cert == nil || c.cert.Leaf.NotAfter.Sub(now) < serverCertRenewAt || !issuedBy(c.cert.Leaf, ca)
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
	cert, err := ca.ServerCertificate(hosts, serverCertTTL)
	if err != nil {
		if !force && c.cert != nil && now.Before(c.cert.Leaf.NotAfter) {
			log.Printf("fleet: could not renew the listener certificate, keeping the current one: %v", err)
			return c.cert, nil
		}
		return nil, err
	}
	c.cert, c.hosts = &cert, hosts
	log.Printf("fleet: listener certificate issued for %s, valid until %s", strings.Join(hosts, ", "), cert.Leaf.NotAfter.UTC().Format(time.DateOnly))
	return c.cert, nil
}

// currentListenerCert is the certificate being served, without renewing it (nil before the first).
func (s *Service) currentListenerCert() (*tls.Certificate, []string) {
	s.srvCert.mu.Lock()
	defer s.srvCert.mu.Unlock()
	return s.srvCert.cert, slices.Clone(s.srvCert.hosts)
}
