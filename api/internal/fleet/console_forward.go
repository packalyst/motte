package fleet

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/auth"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// Port forwarding lets an operator reach a TCP service the fleet machine can see (e.g. a web UI on
// the host's localhost) through the panel, tunneled over the already-open agent console channel.
// Each proxied HTTP request opens its own stream: the panel asks the agent to dial host:port and
// relays raw bytes both ways through a fwdConn (a net.Conn backed by fwd-data frames), which an
// httputil.ReverseProxy drives. Gated exactly like the console (operator+, in scope, console on),
// and each forward is owner-bound. It is deliberately HTTP-only — a browser can't speak raw TCP.

// ---- fwdConn: a net.Conn whose bytes travel as fwd-data frames over the agent channel -----------

type fwdConn struct {
	a         *agentConn
	id        string
	readBuf   chan []byte
	leftover  []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *fwdConn) Read(p []byte) (int, error) {
	if len(c.leftover) == 0 {
		select {
		case b, ok := <-c.readBuf:
			if !ok {
				return 0, io.EOF
			}
			c.leftover = b
		case <-c.closed:
			return 0, io.EOF
		}
	}
	n := copy(p, c.leftover)
	c.leftover = c.leftover[n:]
	return n, nil
}

func (c *fwdConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	c.a.writeToAgent(consoleFrame{T: "fwd-data", Fwd: c.id, Data: base64.StdEncoding.EncodeToString(p)})
	return len(p), nil
}

func (c *fwdConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.a.fwdDelete(c.id)
		c.a.writeToAgent(consoleFrame{T: "fwd-close", Fwd: c.id})
	})
	return nil
}

func (c *fwdConn) deliver(b []byte) {
	select {
	case c.readBuf <- b:
	case <-c.closed:
	}
}

type fwdAddr struct{}

func (fwdAddr) Network() string { return "fwd" }
func (fwdAddr) String() string  { return "fwd" }

func (c *fwdConn) LocalAddr() net.Addr                { return fwdAddr{} }
func (c *fwdConn) RemoteAddr() net.Addr               { return fwdAddr{} }
func (c *fwdConn) SetDeadline(t time.Time) error      { return nil }
func (c *fwdConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fwdConn) SetWriteDeadline(t time.Time) error { return nil }

// ---- agentConn forward-stream plumbing ----------------------------------------------------------

// fwdNew opens a new tunnel stream: it tells the agent to dial host:port and returns the net.Conn.
func (a *agentConn) fwdNew(host string, port int) *fwdConn {
	buf := make([]byte, 12)
	rand.Read(buf)
	c := &fwdConn{a: a, id: hex.EncodeToString(buf), readBuf: make(chan []byte, 64), closed: make(chan struct{})}
	a.fwdMu.Lock()
	a.fwdStreams[c.id] = c
	a.fwdMu.Unlock()
	a.writeToAgent(consoleFrame{T: "fwd-open", Fwd: c.id, Path: host, Port: port})
	return c
}

func (a *agentConn) fwdDelete(id string) {
	a.fwdMu.Lock()
	delete(a.fwdStreams, id)
	a.fwdMu.Unlock()
}

// fwdRoute delivers an agent fwd-data/fwd-close frame to its stream's net.Conn.
func (a *agentConn) fwdRoute(f consoleFrame) {
	a.fwdMu.Lock()
	c := a.fwdStreams[f.Fwd]
	a.fwdMu.Unlock()
	if c == nil {
		return
	}
	if f.T == "fwd-close" {
		c.Close()
		return
	}
	if f.Data != "" {
		if b, err := base64.StdEncoding.DecodeString(f.Data); err == nil {
			c.deliver(b)
		}
	}
}

// ---- forward registry + HTTP handlers -----------------------------------------------------------

type forwardCfg struct {
	machineID string
	host      string
	port      int
	userID    int64
	name      string
	expires   time.Time
}

var (
	fwdCfgMu sync.Mutex
	fwdCfgs  = map[string]*forwardCfg{}
)

const forwardTTL = 2 * time.Hour

// handleConsoleForward creates a port-forward and returns its id + proxy URL. Operator+, in scope,
// console-enabled, owner-bound. POST /api/fleet/console/forward {machine_id, host, port, name}
func (s *Service) handleConsoleForward(w http.ResponseWriter, r *http.Request) {
	p := router.CurrentUser(r)
	var req struct {
		MachineID string `json:"machine_id"`
		Host      string `json:"host"`
		Port      int    `json:"port"`
		Name      string `json:"name"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if p == nil {
		router.JSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	m, err := s.machineByID(req.MachineID)
	if err != nil || m == nil {
		router.JSONError(w, "unknown machine", http.StatusNotFound)
		return
	}
	if !scopeAllows(p, *m) {
		router.JSONError(w, "machine out of scope", http.StatusForbidden)
		return
	}
	if !m.ConsoleEnabled {
		router.JSONError(w, "console is not enabled for this machine", http.StatusForbidden)
		return
	}
	if req.Host == "" {
		req.Host = "localhost"
	}
	if req.Port < 1 || req.Port > 65535 {
		router.JSONError(w, "port must be 1-65535", http.StatusBadRequest)
		return
	}
	buf := make([]byte, 9)
	rand.Read(buf)
	id := base64.RawURLEncoding.EncodeToString(buf)
	fwdCfgMu.Lock()
	for k, c := range fwdCfgs { // sweep expired
		if time.Now().After(c.expires) {
			delete(fwdCfgs, k)
		}
	}
	fwdCfgs[id] = &forwardCfg{machineID: m.ID, host: req.Host, port: req.Port, userID: p.UserID, name: req.Name, expires: time.Now().Add(forwardTTL)}
	fwdCfgMu.Unlock()
	events.Audit("fleet", "console_forward", events.SeverityWarning, p.Username, helper.GetClientIP(r),
		fmt.Sprintf("Port forward opened to %s:%d on %q", req.Host, req.Port, m.Name))
	router.JSON(w, map[string]any{"id": id, "url": "/api/fleet/console/fwd/" + id + "/", "expiresInSec": int(forwardTTL.Seconds())})
}

// HandleConsoleForwardProxy reverse-proxies an HTTP request through the forward's agent tunnel.
// Mounted directly on the mux (streaming + wildcard path), so it self-authenticates and enforces
// operator+ and that the caller owns the forward. GET/POST/… /api/fleet/console/fwd/{id}/...
func (s *Service) HandleConsoleForwardProxy(w http.ResponseWriter, r *http.Request) {
	token := helper.SessionToken(r)
	pr, ok := router.ResolvePrincipal(token)
	if !ok || pr == nil || pr.Locked || !auth.RoleAtLeast(pr.Role, auth.RoleOperator) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/fleet/console/fwd/")
	id, tail, _ := strings.Cut(rest, "/")
	fwdCfgMu.Lock()
	cfg := fwdCfgs[id]
	fwdCfgMu.Unlock()
	if cfg == nil || time.Now().After(cfg.expires) {
		http.Error(w, "unknown or expired forward", http.StatusNotFound)
		return
	}
	if cfg.userID != pr.UserID { // a forward is private to the operator who created it
		http.Error(w, "forward belongs to another operator", http.StatusForbidden)
		return
	}
	a := regGet(cfg.machineID)
	if a == nil {
		http.Error(w, "the machine's console agent is offline", http.StatusBadGateway)
		return
	}
	target := &url.URL{Scheme: "http", Host: net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port))}
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			req.URL.Path = "/" + tail
		},
		Transport: &http.Transport{
			// Every connection the proxy makes is a fresh tunnel stream to host:port via the agent.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return a.fwdNew(cfg.host, cfg.port), nil
			},
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			http.Error(w, "forward error: "+err.Error(), http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}
