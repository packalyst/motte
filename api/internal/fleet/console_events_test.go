package fleet

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"api/internal/auth"
	"api/internal/router"

	"github.com/gorilla/websocket"
)

// The console-events socket re-checks access while open: a scope change applies, and demoting,
// locking or ending the session closes it.
func TestConsoleEventsRecheck(t *testing.T) {
	svc := newTestService(t)
	saved := consoleRecheck
	consoleRecheck = 100 * time.Millisecond
	t.Cleanup(func() { consoleRecheck = saved })

	var mu sync.Mutex
	current := map[string]*router.Principal{}
	set := func(token string, p *router.Principal) { mu.Lock(); current[token] = p; mu.Unlock() }
	router.SetAuthResolver(func(token string) (*router.Principal, bool) {
		mu.Lock()
		defer mu.Unlock()
		p, ok := current[token]
		return p, ok && p != nil
	})
	t.Cleanup(func() { router.SetAuthResolver(nil) })

	srv := httptest.NewServer(http.HandlerFunc(svc.HandleConsoleEvents))
	defer srv.Close()
	open := func(token string) *websocket.Conn {
		h := http.Header{"Authorization": {"Bearer " + token}}
		c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), h)
		if err != nil {
			t.Fatalf("%s: %v", token, err)
		}
		return c
	}
	// alive: the socket answers a refresh (after its initial push).
	alive := func(c *websocket.Conn) bool {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := c.WriteJSON(map[string]string{"t": "refresh"}); err != nil {
			return false
		}
		_, _, err := c.ReadMessage()
		return err == nil
	}
	// closed: the server ends the socket (reads fail with something other than our deadline).
	closed := func(c *websocket.Conn) bool {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return !strings.Contains(err.Error(), "timeout")
			}
		}
	}

	operator := &router.Principal{UserID: 7, Username: "op", Role: auth.RoleOperator}
	for _, c := range []struct {
		name   string
		change *router.Principal // nil = session ended
	}{
		{"demoted", &router.Principal{UserID: 7, Username: "op", Role: auth.RoleViewer}},
		{"locked", &router.Principal{UserID: 7, Username: "op", Role: auth.RoleOperator, Locked: true}},
		{"ended", nil},
	} {
		token := "tok-" + c.name
		set(token, operator)
		conn := open(token)
		time.Sleep(3 * consoleRecheck) // several re-checks while access is fine
		if !alive(conn) {
			t.Fatalf("%s: closed while access was fine", c.name)
		}
		set(token, c.change)
		if !closed(conn) {
			t.Errorf("%s: still open after access ended", c.name)
		}
		conn.Close()
	}

	// A scope change is picked up (the principal the socket acts as is refreshed).
	set("tok-scope", operator)
	conn := open("tok-scope")
	defer conn.Close()
	scoped := &router.Principal{UserID: 7, Username: "op", Role: auth.RoleOperator, ScopeKind: "machines", ScopeValues: "m-other"}
	set("tok-scope", scoped)
	deadline := time.Now().Add(2 * time.Second)
	for {
		var seen *router.Principal
		evMu.Lock()
		for sub := range evSubs {
			seen = sub.principal()
		}
		evMu.Unlock()
		if seen != nil && seen.ScopeValues == "m-other" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scope change not applied to the open socket")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
