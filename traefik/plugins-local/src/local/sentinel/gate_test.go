package sentinel

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// listServer serves the gate list; set changes the answer (status 0 = 500).
type listServer struct {
	mu     sync.Mutex
	body   string
	status int
	srv    *httptest.Server
}

func newListServer(t *testing.T, body string) *listServer {
	l := &listServer{body: body, status: http.StatusOK}
	l.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		w.WriteHeader(l.status)
		io.WriteString(w, l.body)
	}))
	t.Cleanup(l.srv.Close)
	return l
}

func (l *listServer) set(status int, body string) {
	l.mu.Lock()
	l.status, l.body = status, body
	l.mu.Unlock()
}

// expire makes the cache refetch on next use.
func expire(c *remoteCache) {
	c.mu.Lock()
	c.fetchedAt = time.Time{}
	c.mu.Unlock()
}

func gateReq(remote, path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
	r.RemoteAddr = remote
	return r
}

func TestParseGateList(t *testing.T) {
	if l, ok := parseGateList([]byte("off\n")).(*gateList); !ok || l.on {
		t.Fatal("off not parsed")
	}
	l, ok := parseGateList([]byte("on\n198.51.100.0/24\n2001:db8::/32\n")).(*gateList)
	if !ok || !l.on || !l.sources.contains(net.ParseIP("198.51.100.9")) || !l.sources.contains(net.ParseIP("2001:db8::1")) ||
		l.sources.contains(net.ParseIP("203.0.113.1")) {
		t.Fatal("on list not parsed")
	}
	for _, bad := range []string{"", "maybe\n1.2.3.4", "<html>error</html>"} {
		if parseGateList([]byte(bad)) != nil {
			t.Errorf("%q accepted as a list", bad)
		}
	}
}

// Only listed peers pass while on; everyone while off; nobody before the list is known; an ACME
// challenge token always; forwarded headers never count.
func TestGateAdmits(t *testing.T) {
	ls := newListServer(t, "on\n198.51.100.0/24\n")
	g := newGate(&GateConfig{ListURL: ls.srv.URL, CacheTTL: 60})

	if !g.admits(gateReq("203.0.113.5:4000", "/.well-known/acme-challenge/Ab-9_x")) {
		t.Fatal("ACME challenge refused")
	}
	for _, p := range []string{"/.well-known/acme-challenge/../admin", "/.well-known/acme-challenge/a/b", "/.well-known/acme-challenge/", "/.well-known/acme-challenge/a.b"} {
		if g.admits(gateReq("203.0.113.5:4000", p)) {
			t.Errorf("%q passed as an ACME challenge", p)
		}
	}
	if !g.admits(gateReq("198.51.100.7:4000", "/")) {
		t.Fatal("listed source refused")
	}
	spoofed := gateReq("203.0.113.5:4000", "/")
	spoofed.Header.Set("CF-Connecting-IP", "198.51.100.7")
	spoofed.Header.Set("X-Forwarded-For", "198.51.100.7")
	if g.admits(spoofed) {
		t.Fatal("forwarded headers let an unlisted source in")
	}

	// A failed fetch keeps the last list.
	ls.set(http.StatusInternalServerError, "")
	expire(g.list)
	if g.admits(gateReq("203.0.113.5:4000", "/")) || !g.admits(gateReq("198.51.100.7:4000", "/")) {
		t.Fatal("a failed fetch changed the list")
	}
	ls.set(http.StatusOK, "garbage")
	expire(g.list)
	if g.admits(gateReq("203.0.113.5:4000", "/")) {
		t.Fatal("an invalid answer opened the gate")
	}

	ls.set(http.StatusOK, "off\n")
	expire(g.list)
	if !g.admits(gateReq("203.0.113.5:4000", "/")) {
		t.Fatal("off still filters")
	}

	// Never fetched (panel unreachable): closed, except ACME.
	cold := newGate(&GateConfig{ListURL: "http://127.0.0.1:1/unreachable"})
	if cold.admits(gateReq("198.51.100.7:4000", "/")) {
		t.Fatal("an unknown list let a request through")
	}
	if !cold.admits(gateReq("203.0.113.5:4000", "/.well-known/acme-challenge/tok")) {
		t.Fatal("ACME refused while the list is unknown")
	}
}

// Drops are batched to the panel once, bounded per address and in addresses.
func TestGateReportsDrops(t *testing.T) {
	got := make(chan string, 4)
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	defer rs.Close()
	g := newGate(&GateConfig{ListURL: "http://unused", ReportURL: rs.URL})

	for i := 0; i < maxGateReportCount+5; i++ {
		g.recordDrop(net.ParseIP("203.0.113.5"))
	}
	g.recordDrop(net.ParseIP("203.0.113.6"))
	for i := 0; i < maxGateReportIPs+10; i++ {
		g.recordDrop(net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)))
	}
	g.mu.Lock()
	n := len(g.drops)
	g.mu.Unlock()
	if n != maxGateReportIPs {
		t.Fatalf("%d addresses waiting, want the cap %d", n, maxGateReportIPs)
	}
	g.flush()
	body := <-got
	if !strings.Contains(body, "203.0.113.5 10\n") || !strings.Contains(body, "203.0.113.6 1\n") {
		t.Fatalf("report: %.200q", body)
	}
	if strings.Count(body, "\n") != maxGateReportIPs {
		t.Fatalf("%d lines reported", strings.Count(body, "\n"))
	}
	g.mu.Lock()
	left, pending := len(g.drops), g.pending
	g.mu.Unlock()
	if left != 0 || pending {
		t.Fatal("drops left after the flush")
	}
}

// Through the real middleware and a real connection: a dropped request gets no response at all,
// whatever the error mode; a listed one reaches the next handler.
func TestGateDropsSilently(t *testing.T) {
	ls := newListServer(t, "on\n198.51.100.0/24\n")
	cfg := CreateConfig() // error mode 403: the gate must still drop silently
	cfg.Gate = &GateConfig{ListURL: ls.srv.URL, ReportURL: "http://127.0.0.1:1/unused"}
	h, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "served")
	}), cfg, "gate")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h) // the client connects from 127.0.0.1: not listed
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if line, err := bufio.NewReader(conn).ReadString('\n'); err == nil || line != "" {
		t.Fatalf("got a response from the gate: %q %v", line, err)
	}
	g := h.(*Sentinel).gate
	g.mu.Lock()
	reported := g.drops["127.0.0.1"]
	g.mu.Unlock()
	if reported != 1 {
		t.Fatalf("the drop wasn't recorded for the report (%d)", reported)
	}

	ls.set(http.StatusOK, "on\n127.0.0.0/8\n")
	expire(h.(*Sentinel).gate.list)
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "served" {
		t.Fatalf("listed source: %q", b)
	}
}
