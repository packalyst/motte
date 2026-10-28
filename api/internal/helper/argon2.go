package helper

import "golang.org/x/crypto/argon2"

// MaxConcurrentArgon2 caps simultaneous Argon2id computations across the panel (password hashes
// and checks, backup passphrases): each takes 64 MiB, so a burst queues instead of exhausting
// memory.
const MaxConcurrentArgon2 = 4

// argonSlots holds one token per computation allowed to run at once; the rest wait their turn.
var argonSlots = make(chan struct{}, MaxConcurrentArgon2)

// Argon2IDKey is the only way the panel runs Argon2id: it waits for a free slot, then derives.
func Argon2IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}
