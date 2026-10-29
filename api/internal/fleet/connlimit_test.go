package fleet

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// shortLimits shrinks the listener timeouts for a test.
func shortLimits(t *testing.T) {
	saved := []time.Duration{fleetReadTimeout, fleetWriteTimeout, fleetLargeTransfer}
	fleetReadTimeout, fleetWriteTimeout, fleetLargeTransfer = 300*time.Millisecond, 300*time.Millisecond, 5*time.Second
	t.Cleanup(func() { fleetReadTimeout, fleetWriteTimeout, fleetLargeTransfer = saved[0], saved[1], saved[2] })
}

// serve runs h behind newFleetServer (plain TCP: TLS doesn't change the timeouts).
func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newFleetServer(h, nil)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// trickle sends a POST whose body arrives one byte every gap, and returns the response status (0
// when the server cut the connection).
func trickle(t *testing.T, addr, path string, n int, gap time.Duration) int {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", path, n)
	for i := 0; i < n; i++ {
		time.Sleep(gap)
		if _, err := c.Write([]byte("x")); err != nil {
			return 0
		}
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0
	}
	return resp.StatusCode
}

// A body trickled past the read timeout is cut; an endpoint that allows a large transfer gets
// the longer deadline.
func TestFleetListenerSlowBody(t *testing.T) {
	shortLimits(t)
	mux := http.NewServeMux()
	readErr := make(chan error, 2) // what the server's body read ended with, per request
	readAll := func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		readErr <- err
		if err == nil {
			w.WriteHeader(http.StatusOK)
		}
	}
	mux.HandleFunc("/small", readAll)
	mux.HandleFunc("/large", func(w http.ResponseWriter, r *http.Request) { allowLargeTransfer(w); readAll(w, r) })
	addr := serve(t, mux)

	if code := trickle(t, addr, "/small", 8, 100*time.Millisecond); code == http.StatusOK {
		t.Fatal("a body trickled past the read timeout was accepted")
	}
	if err := <-readErr; err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("the server kept reading a trickled body: %v", err)
	}
	if code := trickle(t, addr, "/large", 8, 100*time.Millisecond); code != http.StatusOK {
		t.Fatalf("a large transfer was cut at the normal timeout: %d", code)
	}
	if err := <-readErr; err != nil {
		t.Fatalf("a large transfer's read failed: %v", err)
	}
}

// The console and link WebSockets outlive the request timeouts: the upgrade clears them.
func TestFleetListenerWebSocketOutlivesTimeouts(t *testing.T) {
	shortLimits(t)
	up := websocket.Upgrader{}
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			c.WriteMessage(mt, msg)
		}
	}))
	ws, _, err := websocket.DefaultDialer.Dial("ws://"+addr+"/console", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	time.Sleep(time.Second) // well past the read and write timeouts
	if err := ws.WriteMessage(websocket.TextMessage, []byte("still here")); err != nil {
		t.Fatalf("write after the timeouts: %v", err)
	}
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, msg, err := ws.ReadMessage(); err != nil || string(msg) != "still here" {
		t.Fatalf("the WebSocket didn't survive the timeouts: %q %v", msg, err)
	}
}

// A client gets at most max open connections; a closed one frees its place.
func TestFleetListenerPerIPCap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := limitPerIP(ln, 2)
	defer limited.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := limited.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	refused := func(c net.Conn) bool { // the server closed it at once
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, err := c.Read(make([]byte, 1))
		return err != nil && !strings.Contains(err.Error(), "timeout")
	}
	a, b := dial(), dial()
	<-accepted
	sb := <-accepted
	third := dial()
	if !refused(third) {
		t.Fatal("a third connection from the same address was accepted")
	}
	sb.Close() // the server side of b goes: a place frees up
	b.Close()
	fourth := dial()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("no place came free after a connection closed")
	}
	a.Close()
	fourth.Close()
}
