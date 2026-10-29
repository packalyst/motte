package helper

import "golang.org/x/crypto/argon2"

// argonSlots holds one token per computation allowed to run at once (MaxConcurrentArgon2: password
// hashes and checks, backup passphrases take 64 MiB each), so a burst queues instead of exhausting
// memory; the rest wait their turn.
var argonSlots = make(chan struct{}, MaxConcurrentArgon2)

// Argon2IDKey is the only way the panel runs Argon2id: it waits for a free slot, then derives.
func Argon2IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}
