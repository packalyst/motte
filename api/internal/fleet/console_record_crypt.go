package fleet

// Recordings are encrypted at rest with envelope encryption. Each recording file gets its own random
// 256-bit data key, and that key is stored ONLY in the database (fleet_console_rec_keys), wrapped with
// the panel's ENCRYPTION_SECRET — which lives in .env, not on the data volume. So:
//   - the recordings folder, a copy of the volume or a disk snapshot is unreadable on its own;
//   - key rotation (manage.sh rotate-key) re-wraps these keys with every other secret (rekey package),
//     the files themselves are never rewritten;
//   - deleting a recording deletes its key, so any copy of the file left behind (snapshots, folder
//     backups) becomes permanently unreadable.
// It does NOT protect against root on the running panel host, which holds both the key and the files.
//
// File format: recMagic, then records: uint32 big-endian length | 12-byte nonce | AES-256-GCM
// ciphertext. Record 0 is the asciicast header line, every later record one event line. Each record
// is authenticated with the file name and its sequence number, so records can't be moved between
// files, reordered or dropped from the middle undetected. A half-written trailing record (crash) is
// ignored on read and trimmed before the next append.

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"api/internal/helper"
)

var recMagic = []byte("WGREC1\n")

const recMaxRecord = 16 << 20 // sanity bound on one record's length when reading

// recordDB is the panel database holding the wrapped recording keys (set by New).
var recordDB *sql.DB

var errRecNoKey = errors.New("recording key not found")

func recAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// newRecKey creates and stores a fresh data key for a new recording file (replacing a stale row left
// by a file that no longer exists).
func newRecKey(name string) (cipher.AEAD, error) {
	if recordDB == nil {
		return nil, errors.New("recording key store unavailable")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	wrapped, err := helper.Encrypt(hex.EncodeToString(key))
	if err != nil {
		return nil, err
	}
	if _, err := recordDB.Exec(`INSERT OR REPLACE INTO fleet_console_rec_keys (name, key_enc, created_at) VALUES (?, ?, ?)`,
		name, wrapped, time.Now().Unix()); err != nil {
		return nil, err
	}
	return recAEAD(key)
}

func loadRecKey(name string) (cipher.AEAD, error) {
	if recordDB == nil {
		return nil, errors.New("recording key store unavailable")
	}
	var wrapped string
	if err := recordDB.QueryRow(`SELECT key_enc FROM fleet_console_rec_keys WHERE name=?`, name).Scan(&wrapped); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errRecNoKey
		}
		return nil, err
	}
	h, err := helper.Decrypt(wrapped)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(h)
	if err != nil || len(key) != 32 {
		return nil, errors.New("recording key is malformed")
	}
	return recAEAD(key)
}

func deleteRecKey(name string) error {
	if recordDB == nil {
		return errors.New("recording key store unavailable")
	}
	_, err := recordDB.Exec(`DELETE FROM fleet_console_rec_keys WHERE name=?`, name)
	return err
}

// pruneRecKeys drops keys whose file is gone (removed outside the panel). Rows younger than an hour
// are left alone so a key is never pruned between its creation and its file's.
func pruneRecKeys(dir string) {
	if recordDB == nil {
		return
	}
	rows, err := recordDB.Query(`SELECT name FROM fleet_console_rec_keys WHERE created_at < ?`, time.Now().Add(-time.Hour).Unix())
	if err != nil {
		return
	}
	var gone []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			if _, err := os.Stat(filepath.Join(dir, n)); os.IsNotExist(err) {
				gone = append(gone, n)
			}
		}
	}
	rows.Close()
	for _, n := range gone {
		deleteRecKey(n)
	}
}

func recAAD(name string, seq uint64) []byte {
	b := make([]byte, 0, len(name)+9)
	b = append(b, name...)
	b = append(b, 0)
	return binary.BigEndian.AppendUint64(b, seq)
}

// sealRecord returns one complete on-disk record (length prefix included), written with a single
// Write so a record is never interleaved.
func sealRecord(aead cipher.AEAD, name string, seq uint64, plain []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	body := aead.Seal(nonce, nonce, plain, recAAD(name, seq))
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...), nil
}

// walkRecords reads the records of an encrypted recording in order, handing fn each sealed body
// (nonce+ciphertext). It returns the offset just past the last complete record and the record count;
// a truncated trailing record is not an error.
func walkRecords(r io.Reader, fn func(seq uint64, body []byte) error) (end int64, n uint64, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	magic := make([]byte, len(recMagic))
	if _, err := io.ReadFull(br, magic); err != nil || !bytes.Equal(magic, recMagic) {
		return 0, 0, errors.New("not an encrypted recording")
	}
	end = int64(len(recMagic))
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return end, n, nil // clean EOF or a cut-off length prefix
		}
		size := binary.BigEndian.Uint32(hdr[:])
		if size == 0 || size > recMaxRecord {
			return end, n, errors.New("recording is corrupted")
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(br, body); err != nil {
			return end, n, nil // half-written trailing record
		}
		if fn != nil {
			if err := fn(n, body); err != nil {
				return end, n, err
			}
		}
		end += 4 + int64(size)
		n++
	}
}

func openRecord(aead cipher.AEAD, name string, seq uint64, body []byte) ([]byte, error) {
	ns := aead.NonceSize()
	if len(body) < ns {
		return nil, errors.New("recording is corrupted")
	}
	plain, err := aead.Open(nil, body[:ns], body[ns:], recAAD(name, seq))
	if err != nil {
		return nil, errors.New("recording failed integrity check")
	}
	return plain, nil
}

var errStopWalk = errors.New("stop")

// readRecHeader decrypts just a recording's header record.
func readRecHeader(path string) (recHeader, error) {
	var h recHeader
	f, err := os.Open(path)
	if err != nil {
		return h, err
	}
	defer f.Close()
	name := filepath.Base(path)
	aead, err := loadRecKey(name)
	if err != nil {
		return h, err
	}
	var plain []byte
	_, _, err = walkRecords(f, func(seq uint64, body []byte) error {
		p, err := openRecord(aead, name, seq, body)
		if err != nil {
			return err
		}
		plain = p
		return errStopWalk
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		return h, err
	}
	if plain == nil {
		return h, errors.New("recording has no header")
	}
	err = json.Unmarshal(plain, &h)
	return h, err
}

// decryptRecording returns the whole recording as plain asciicast text.
func decryptRecording(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	name := filepath.Base(path)
	aead, err := loadRecKey(name)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	_, _, err = walkRecords(f, func(seq uint64, body []byte) error {
		p, err := openRecord(aead, name, seq, body)
		if err != nil {
			return err
		}
		out.Write(p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
