package wireguard

import (
	"os"
	"path/filepath"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The public key is derived from the private one: a missing public-key file must not make the
// server generate a new identity (which would cut off every client).
func TestInitServerKeysKeepsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server_private.key"), []byte(key.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Service{config: Config{DataDir: dir}}
	if err := s.initServerKeys(); err != nil {
		t.Fatal(err)
	}
	priv, pub := s.serverKeys()
	if priv != key.String() || pub != key.PublicKey().String() {
		t.Fatalf("keys = %s / %s, want the stored key and its public half", priv, pub)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "server_public.key")); string(b) != key.PublicKey().String() {
		t.Fatalf("public key file = %q", b)
	}
}

func TestInitServerKeysGeneratesOnFirstStart(t *testing.T) {
	s := &Service{config: Config{DataDir: t.TempDir()}}
	if err := s.initServerKeys(); err != nil {
		t.Fatal(err)
	}
	priv, pub := s.serverKeys()
	key, err := wgtypes.ParseKey(priv)
	if err != nil || key.PublicKey().String() != pub {
		t.Fatalf("generated keys don't match: %v", err)
	}
}

func TestReplaceServerKeyRejectsJunk(t *testing.T) {
	s := &Service{config: Config{DataDir: t.TempDir()}}
	if err := s.ReplaceServerKey("not-a-key"); err == nil {
		t.Fatal("junk accepted as a WireGuard key")
	}
}
