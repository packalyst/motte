package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
)

var encryptionKey []byte

// WeakEncryptionKey is set true when ENCRYPTION_SECRET was NOT a proper 32-byte hex key and
// we had to fall back to a single unsalted SHA-256 of the raw string. That key is far more
// brute-forceable than a real 256-bit random key, so main() surfaces this to the Activity
// feed (in addition to the startup-log warning below) recommending rotation.
var WeakEncryptionKey bool

// ParseKey turns an ENCRYPTION_SECRET string into a 32-byte AES key using the
// same rule everywhere: a 32-byte hex string is used directly; anything else
// falls back to SHA-256 of the raw string (weak=true). Kept in one place so the
// live process key and the rotation tool derive keys identically — otherwise
// re-encrypted data could not be read back.
func ParseKey(secret string) (key []byte, weak bool) {
	if k, err := hex.DecodeString(secret); err == nil && len(k) == 32 {
		return k, false
	}
	h := sha256.Sum256([]byte(secret))
	return h[:], true
}

// InitEncryption initializes the process encryption key from environment.
// Must be called early in main() before any encryption/decryption operations.
func InitEncryption() {
	keyHex := os.Getenv("ENCRYPTION_SECRET")
	if keyHex == "" {
		log.Fatal("FATAL: ENCRYPTION_SECRET environment variable is required but not set. Generate one with: openssl rand -hex 32")
	}
	encryptionKey, WeakEncryptionKey = ParseKey(keyHex)
	if WeakEncryptionKey {
		// Materially weaker than a real random key; changing the derivation later would
		// make existing ciphertext undecryptable, so we keep it and flag for rotation.
		log.Printf("WARNING: ENCRYPTION_SECRET is not a 32-byte hex key — using a weaker SHA-256-derived key. Rotate to a strong key (openssl rand -hex 32) with: wire-panel rotate-key")
	}
}

// EncryptWith encrypts a string with an explicit AES-256-GCM key. A fresh random
// nonce is prepended to the ciphertext, then the whole thing is base64-encoded.
func EncryptWith(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWith decrypts a value produced by EncryptWith using an explicit key.
func DecryptWith(key []byte, ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, cipherData := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// Encrypt encrypts a string value using the process key (AES-256-GCM).
func Encrypt(plaintext string) (string, error) {
	if encryptionKey == nil {
		return "", errors.New("encryption not initialized")
	}
	return EncryptWith(encryptionKey, plaintext)
}

// Decrypt decrypts an AES-256-GCM value using the process key.
func Decrypt(ciphertext string) (string, error) {
	if encryptionKey == nil {
		return "", errors.New("encryption not initialized")
	}
	return DecryptWith(encryptionKey, ciphertext)
}
