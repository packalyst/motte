package helper

import (
	"testing"
	"time"
)

// TestArgon2Cap: with every slot taken, a derivation waits instead of running.
func TestArgon2Cap(t *testing.T) {
	for i := 0; i < MaxConcurrentArgon2; i++ {
		argonSlots <- struct{}{}
	}
	done := make(chan struct{})
	go func() { Argon2IDKey([]byte("x"), []byte("synthetic-salt"), 1, 64*1024, 1, 32); close(done) }()
	select {
	case <-done:
		t.Fatal("Argon2id ran with no free slot")
	case <-time.After(200 * time.Millisecond):
	}
	<-argonSlots // free one
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Argon2id did not run once a slot was free")
	}
	for i := 1; i < MaxConcurrentArgon2; i++ {
		<-argonSlots
	}
}
