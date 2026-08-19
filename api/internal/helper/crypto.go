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

// InitEncryption initializes the encryption key from environment.
// Must be called early in main() before any encryption/decryption operations.
func InitEncryption() {
	keyHex := os.Getenv("ENCRYPTION_SECRET")
	if keyHex == "" {
		log.Fatal("FATAL: ENCRYPTION_SECRET environment variable is required but not set. Generate one with: openssl rand -hex 32")
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		// Not a 32-byte hex key: fall back to SHA-256 of the raw string so any secret still
		// works, but WARN — this is materially weaker than a real random key and secrets at
		// rest (WG keys, TOTP, fleet CA) inherit that weakness. Changing the derivation later
		// would make existing ciphertext undecryptable, so we keep it and flag for rotation.
		log.Printf("WARNING: ENCRYPTION_SECRET is not a 32-byte hex key — using a weaker SHA-256-derived key. Rotate to a strong key: openssl rand -hex 32 (note: rotating re-keys and invalidates existing encrypted secrets).")
		WeakEncryptionKey = true
		hash := sha256.Sum256([]byte(keyHex))
		encryptionKey = hash[:]
		return
	}
	encryptionKey = key
}

// Encrypt encrypts a string value using AES-256-GCM
func Encrypt(plaintext string) (string, error) {
	if encryptionKey == nil {
		return "", errors.New("encryption not initialized")
	}

	block, err := aes.NewCipher(encryptionKey)
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

// Decrypt decrypts an AES-256-GCM encrypted string
func Decrypt(ciphertext string) (string, error) {
	if encryptionKey == nil {
		return "", errors.New("encryption not initialized")
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
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
