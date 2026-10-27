package backup

// Off-host backup: scheduled, automated upload of a passphrase-sealed backup (the same Export()
// bundle a user can download by hand) to S3-compatible storage and/or SFTP, so a total host loss
// is recoverable. The bundle is already Argon2id+AES-GCM sealed by Export, so it is encrypted
// before it leaves the host; destination credentials and the stored passphrase are kept encrypted
// at rest (helper.Encrypt) in a single config blob.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"api/internal/helper"
)

// Destination is one off-host target. Type is "s3" or "sftp"; only the matching fields are used.
type Destination struct {
	ID   string `json:"id"`
	Type string `json:"type"` // "s3" | "sftp"
	Name string `json:"name"` // operator-facing label

	// S3-compatible (AWS S3, Backblaze B2, Cloudflare R2, MinIO, Wasabi…)
	Endpoint  string `json:"endpoint,omitempty"` // host[:port], e.g. s3.amazonaws.com
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	AccessKey string `json:"accessKey,omitempty"`
	SecretKey string `json:"secretKey,omitempty"` // secret (write-only to the UI)
	UseSSL    bool   `json:"useSSL"`

	// SFTP
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	User       string `json:"user,omitempty"`
	Password   string `json:"password,omitempty"`   // secret (write-only)
	PrivateKey string `json:"privateKey,omitempty"` // PEM, optional (secret, write-only)
	Path       string `json:"path,omitempty"`       // remote directory
	HostKey    string `json:"hostKey,omitempty"`    // pinned SSH host key (authorized_keys line); not secret
}

// OffhostConfig is the scheduled-backup policy, persisted as one encrypted JSON blob.
type OffhostConfig struct {
	Enabled      bool          `json:"enabled"` // run the daily scheduled backup
	Hour         int           `json:"hour"`    // local hour (0-23) for the daily run
	Passphrase   string        `json:"passphrase"`
	IncludeUsers bool          `json:"includeUsers"` // mirror Export's opt-in tiers
	IncludeFleet bool          `json:"includeFleet"`
	KeepN        int           `json:"keepN"` // archives to retain per destination
	Destinations []Destination `json:"destinations"`
}

var offhostCfgOnce sync.Once

func (s *Service) ensureOffhostTable() {
	offhostCfgOnce.Do(func() {
		if db := s.db(); db != nil {
			db.Exec(`CREATE TABLE IF NOT EXISTS backup_offhost_config (
				id         INTEGER PRIMARY KEY CHECK (id = 1),
				config_enc TEXT NOT NULL
			)`)
		}
	})
}

func (s *Service) loadOffhostConfig() (OffhostConfig, error) {
	s.ensureOffhostTable()
	db := s.db()
	if db == nil {
		return OffhostConfig{}, errors.New("database unavailable")
	}
	var enc string
	err := db.QueryRow("SELECT config_enc FROM backup_offhost_config WHERE id = 1").Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return OffhostConfig{KeepN: 14, Hour: 3}, nil
	}
	if err != nil {
		return OffhostConfig{}, err
	}
	plain, err := helper.Decrypt(enc)
	if err != nil {
		return OffhostConfig{}, err
	}
	var c OffhostConfig
	if err := json.Unmarshal([]byte(plain), &c); err != nil {
		return OffhostConfig{}, err
	}
	return c, nil
}

func (s *Service) saveOffhostConfig(c OffhostConfig) error {
	s.ensureOffhostTable()
	db := s.db()
	if db == nil {
		return errors.New("database unavailable")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	enc, err := helper.Encrypt(string(raw))
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO backup_offhost_config (id, config_enc) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET config_enc = excluded.config_enc`, enc)
	return err
}

// redactedSecret is returned in place of a stored secret and recognised on save to mean "keep the
// existing value". Chosen so it can never be a real credential.
const redactedSecret = "__stored__"

func (c OffhostConfig) masked() OffhostConfig {
	out := c
	out.Passphrase = maskSecret(c.Passphrase)
	out.Destinations = make([]Destination, len(c.Destinations))
	for i, d := range c.Destinations {
		d.SecretKey = maskSecret(d.SecretKey)
		d.Password = maskSecret(d.Password)
		d.PrivateKey = maskSecret(d.PrivateKey)
		out.Destinations[i] = d
	}
	return out
}

func maskSecret(v string) string {
	if v == "" {
		return ""
	}
	return redactedSecret
}

// mergeSecrets folds the UI's config onto the stored one so secrets never have to be echoed back:
// a redacted placeholder keeps the stored value, "" clears it, anything else replaces it.
func mergeSecrets(incoming, stored OffhostConfig) OffhostConfig {
	out := incoming
	if incoming.Passphrase == redactedSecret {
		out.Passphrase = stored.Passphrase
	}
	byID := map[string]Destination{}
	for _, d := range stored.Destinations {
		byID[d.ID] = d
	}
	for i, d := range out.Destinations {
		out.Destinations[i] = mergeDestinationSecretsFrom(d, byID[d.ID])
	}
	return out
}

func mergeDestinationSecretsFrom(d, prev Destination) Destination {
	if d.SecretKey == redactedSecret {
		d.SecretKey = prev.SecretKey
	}
	if d.Password == redactedSecret {
		d.Password = prev.Password
	}
	if d.PrivateKey == redactedSecret {
		d.PrivateKey = prev.PrivateKey
	}
	switch {
	case !sameSSHServer(d, prev):
		// The pinned key belongs to the old server: carried to a new one, every backup would fail
		// with a host-key mismatch. The new server is pinned on its first connection instead.
		if d.HostKey == prev.HostKey {
			d.HostKey = ""
		}
	case d.HostKey == "":
		d.HostKey = prev.HostKey
	}
	return d
}

// sameSSHServer reports whether two destinations reach the same SSH server, so a host key pinned
// for one is valid for the other.
func sameSSHServer(a, b Destination) bool {
	return strings.EqualFold(strings.TrimSpace(a.Host), strings.TrimSpace(b.Host)) && sshPort(a) == sshPort(b)
}

func sshPort(d Destination) int {
	if d.Port == 0 {
		return 22
	}
	return d.Port
}

// validate checks a config is coherent enough to run a scheduled backup.
func (c OffhostConfig) validate() error {
	if err := ValidatePassphrase(c.Passphrase); err != nil {
		return err
	}
	if len(c.Destinations) == 0 {
		return errors.New("at least one destination is required")
	}
	for _, d := range c.Destinations {
		switch d.Type {
		case "s3":
			if d.Endpoint == "" || d.Bucket == "" || d.AccessKey == "" {
				return errors.New("S3 destination needs endpoint, bucket and access key")
			}
		case "sftp":
			if d.Host == "" || d.User == "" || (d.Password == "" && d.PrivateKey == "") {
				return errors.New("SFTP destination needs host, user and a password or private key")
			}
		default:
			return errors.New("unknown destination type: " + d.Type)
		}
	}
	return nil
}

func findDest(cfg OffhostConfig, id string) (Destination, bool) {
	for _, d := range cfg.Destinations {
		if d.ID == id {
			return d, true
		}
	}
	return Destination{}, false
}
