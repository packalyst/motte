package wireguard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/database"
	"api/internal/helper"
)

// Editing a peer answers without its private and pre-shared keys (like every other peer reply),
// and the stored peer keeps them.
func TestUpdatePeerReplyHasNoKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	t.Setenv("ENCRYPTION_SECRET", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("PATH", t.TempDir()) // syncConfig's `wg` calls find nothing: the test never touches the host
	helper.InitEncryption()
	if _, err := database.Init(dir); err != nil {
		t.Fatal(err)
	}
	s := &Service{config: Config{DataDir: dir, Interface: "wgtest0"}, peerStore: &PeerStore{cache: map[string]*Peer{}, dataDir: dir}}
	s.peerStore.Add(&Peer{ID: "p1", Name: "laptop", PublicKey: "pub-fake", PrivateKey: "priv-fake", PresharedKey: "psk-fake", IPAddress: "10.8.0.9", Enabled: true})

	w := httptest.NewRecorder()
	s.handleUpdatePeer(w, httptest.NewRequest(http.MethodPut, "/api/wg/peers/p1", strings.NewReader(`{"name":"laptop-2"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Body.String(), "priv-fake") || strings.Contains(w.Body.String(), "psk-fake") {
		t.Fatalf("reply carries a key: %s", w.Body)
	}
	if p := s.peerStore.Get("p1"); p.Name != "laptop-2" || p.PrivateKey != "priv-fake" || p.PresharedKey != "psk-fake" {
		t.Fatalf("stored peer = %+v, want the new name and its keys", p)
	}
}
