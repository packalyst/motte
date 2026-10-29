package fleet

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"api/internal/helper"
)

// Fleet listener limits. The listener is public (agents dial in from anywhere), and it shares the
// API process, so a client must not be able to hold its connections open: every request has to
// send its headers within fleetHeaderTimeout, its whole body within fleetReadTimeout and take its
// answer within fleetWriteTimeout, and an idle keep-alive connection is closed after
// fleetIdleTimeout. The two large transfers (a CVE report, the agent binary) extend their own
// deadlines to fleetLargeTransfer (allowLargeTransfer). The console and link WebSockets clear the
// deadlines when they upgrade. At most helper.MaxFleetConnsPerIP connections stay open per client
// address (an IPv6 client per /64), enough for a whole site of machines behind one NAT. The numbers
// are in helper/limits.go; these are vars so tests can shorten them.
var (
	fleetHeaderTimeout = helper.FleetHeaderTimeout
	fleetReadTimeout   = helper.FleetReadTimeout
	fleetWriteTimeout  = helper.FleetWriteTimeout
	fleetIdleTimeout   = helper.FleetIdleTimeout
	fleetLargeTransfer = helper.FleetLargeTransfer
)

// allowLargeTransfer gives the current request fleetLargeTransfer to send its body and get its
// answer, for the endpoints that move large payloads.
func allowLargeTransfer(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(fleetLargeTransfer)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)
}

// perIPListener refuses (closes at once) a connection from a client that already has max open.
type perIPListener struct {
	net.Listener
	max  int
	mu   sync.Mutex
	open map[string]int // client key (helper.RateKey) → open connections; deleted at zero
}

func limitPerIP(l net.Listener, max int) net.Listener {
	return &perIPListener{Listener: l, max: max, open: map[string]int{}}
}

func (l *perIPListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		key := helper.RateKey(host)
		l.mu.Lock()
		if l.open[key] >= l.max {
			l.mu.Unlock()
			c.Close()
			continue
		}
		l.open[key]++
		l.mu.Unlock()
		return &countedConn{Conn: c, release: func() { l.release(key) }}, nil
	}
}

func (l *perIPListener) release(key string) {
	l.mu.Lock()
	if l.open[key]--; l.open[key] <= 0 {
		delete(l.open, key)
	}
	l.mu.Unlock()
}

// countedConn gives its slot back once, on the first Close.
type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// newFleetServer is the fleet listener's server, with the limits above.
func newFleetServer(h http.Handler, tc *tls.Config) *http.Server {
	return &http.Server{
		Handler:           h,
		TLSConfig:         tc,
		ReadHeaderTimeout: fleetHeaderTimeout,
		ReadTimeout:       fleetReadTimeout,
		WriteTimeout:      fleetWriteTimeout,
		IdleTimeout:       fleetIdleTimeout,
		MaxHeaderBytes:    64 << 10,
	}
}
