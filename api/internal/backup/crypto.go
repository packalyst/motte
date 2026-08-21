package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

// Passphrase sealing for backup files. The config document is sealed with
// AES-256-GCM under a key derived from the user's passphrase (PBKDF2-SHA256).
// This is deliberately independent of the panel's ENCRYPTION_SECRET: a backup must
// restore onto a DIFFERENT host whose ENCRYPTION_SECRET differs, so secrets travel
// as plaintext INSIDE the sealed body and are re-encrypted under the destination
// host on import. The file itself is inert without the passphrase.

const (
	kdfName = "pbkdf2-sha256"
	kdfIter = 600_000 // OWASP 2023 floor for PBKDF2-HMAC-SHA256
	saltLen = 16
	keyLen  = 32 // AES-256
)

// errBadPass is returned for a wrong passphrase or any tampering — GCM auth
// failure is indistinguishable by design, so we never leak which.
const errBadPass = passErr("wrong passphrase or corrupt backup")

type passErr string

func (e passErr) Error() string { return string(e) }

// deriveKey stretches the passphrase into a 256-bit key with the given salt.
func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, kdfIter, keyLen)
}

// seal encrypts plaintext under the passphrase. aad (the cleartext envelope header)
// is authenticated but not encrypted, so a tampered header fails the open. Returns a
// fresh random salt and nonce alongside the ciphertext.
func seal(passphrase string, plaintext, aad []byte) (salt, nonce, ciphertext []byte, err error) {
	salt = make([]byte, saltLen)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, nil, err
	}
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}
	return salt, nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// open reverses seal. A wrong passphrase (or any tampering of ciphertext or aad)
// surfaces as errBadPass, never a partial/garbage plaintext.
func open(passphrase string, salt, nonce, ciphertext, aad []byte) ([]byte, error) {
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errBadPass
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errBadPass
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
