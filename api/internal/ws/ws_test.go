package ws

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api/internal/auth"
	"api/internal/database"
	"api/internal/helper"
)

// The live-updates socket opens only for a valid session presented on the upgrade itself: no
// credential, or a bad one, is refused before the upgrade, so nothing is read from a stranger.
func TestHandshakeNeedsSession(t *testing.T) {
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	svc, err := auth.New()
	if err != nil {
		t.Fatal(err)
	}
	prev := auth.GetService()
	auth.SetService(svc)
	t.Cleanup(func() { auth.SetService(prev) })

	s := &Service{hub: newHub(1)}
	for name, bearer := range map[string]string{"none": "", "bogus": "not-a-session"} {
		r := httptest.NewRequest(http.MethodGet, "/api/ws", nil)
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		s.HandleWebSocket(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401 before any upgrade", name, w.Code)
		}
	}
}

// One user holds at most MaxWSClientsPerUser live sockets; others are not affected, and a
// closed one frees its place.
func TestAdmitCapsPerUser(t *testing.T) {
	h := newHub(1)
	var first *Client
	for i := 0; i < helper.MaxWSClientsPerUser; i++ {
		c := NewClient(h, nil, 7, "u", "admin", "", "")
		if !h.admit(c) {
			t.Fatalf("socket %d refused under the cap", i+1)
		}
		if first == nil {
			first = c
		}
	}
	if h.admit(NewClient(h, nil, 7, "u", "admin", "", "")) {
		t.Fatal("a socket over the cap was admitted")
	}
	if !h.admit(NewClient(h, nil, 8, "other", "viewer", "", "")) {
		t.Fatal("another user is not affected by the cap")
	}
	h.mu.Lock()
	delete(h.clients, first)
	delete(h.userClients[7], first)
	h.mu.Unlock()
	if !h.admit(NewClient(h, nil, 7, "u", "admin", "", "")) {
		t.Fatal("a freed place is usable again")
	}
}
