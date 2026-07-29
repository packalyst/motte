package turbotunnels

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"api/internal/helper"
	"api/internal/settings"
)

// settingKeyConfig is the settings key under which the full tunnel
// configuration is stored, AES-256-GCM encrypted. It is the single source of
// truth for what the container runs — there is no config file on disk.
const settingKeyConfig = "turbotunnels_config"

// minPassLen is the minimum length for a proxy password. Because every tunnel
// is published on 0.0.0.0 (reachable from the internet), a strong password is
// the primary line of defence, so we never persist a weak one. Auto-generated
// passwords are far longer than this floor.
const minPassLen = 12

// Upstream describes an optional upstream proxy to chain through. When Host is
// empty the tunnel is "direct" — it exits from this server's own IP. When Host
// is set the tunnel is "chained" — traffic is forwarded through the upstream
// proxy and exits from the upstream's IP.
type Upstream struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"`
}

// IsSet reports whether an upstream (chained mode) is configured.
func (u Upstream) IsSet() bool {
	return strings.TrimSpace(u.Host) != ""
}

// Tunnel is one HTTP forward-proxy the panel manages. Only HTTP is supported:
// its auth path is verified end-to-end. SOCKS5 is intentionally excluded until
// its auth enforcement is verified, so no tunnel can ever be an open proxy.
type Tunnel struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	ListenPort int      `json:"listenPort"`
	User       string   `json:"user"`
	Pass       string   `json:"pass"`
	Upstream   Upstream `json:"upstream"`
}

// IsDirect reports whether the tunnel exits from this server directly (no
// upstream hop).
func (t Tunnel) IsDirect() bool {
	return !t.Upstream.IsSet()
}

// Config is the full set of managed tunnels — the whole persisted document.
type Config struct {
	Tunnels []Tunnel `json:"tunnels"`
}

// randHexN returns n random bytes hex-encoded (2n chars). Falls back to a fixed
// marker only on the (practically impossible) failure of the system RNG; such a
// value would still be rejected by validation as too weak if used as a password.
func randHexN(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "rng_error"
	}
	return hex.EncodeToString(b)
}

// newTunnelID returns a short unique identifier for a tunnel.
func newTunnelID() string {
	return randHexN(8)
}

// b62Alphabet is the character set for generated passwords: mixed-case letters
// and digits. Deliberately excludes symbols so the password stays URL-safe
// inside "http://user:pass@host:port" and in shell commands.
const b62Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// randPassword returns an n-character base62 password (~5.95 bits/char) using
// rejection sampling for an unbiased distribution. Falls back to hex only if
// the system RNG fails.
func randPassword(n int) string {
	out := make([]byte, 0, n)
	buf := make([]byte, 1)
	// Largest multiple of the alphabet length below 256, to reject the biased tail.
	limit := 256 - (256 % len(b62Alphabet))
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return randHexN(n)
		}
		if int(buf[0]) < limit {
			out = append(out, b62Alphabet[int(buf[0])%len(b62Alphabet)])
		}
	}
	return string(out)
}

// GenCredentials returns a fresh strong username/password pair for a proxy.
// The password is 24 base62 chars (~143 bits of entropy).
func GenCredentials() (user, pass string) {
	return "u_" + randHexN(4), randPassword(24)
}

// isSafeCredential reports whether s is safe to embed in an
// "http://user:pass@host:port" endpoint: printable ASCII with none of the URL
// delimiters ':' '@' '/' and no whitespace. Auto-generated credentials always
// pass; this guards user-entered ones so they can't break URL/auth parsing.
func isSafeCredential(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e { // non-printable, non-ASCII, or space
			return false
		}
		if r == ':' || r == '@' || r == '/' {
			return false
		}
	}
	return true
}

// LoadConfig reads and decrypts the stored tunnel configuration. A missing
// value yields an empty config (no tunnels), never an error, so a fresh install
// starts clean.
func LoadConfig() (Config, error) {
	var cfg Config
	raw, err := settings.GetSettingEncrypted(settingKeyConfig)
	if err != nil || strings.TrimSpace(raw) == "" {
		return cfg, nil
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return Config{}, fmt.Errorf("stored tunnel config is corrupt: %w", err)
	}
	if cfg.Tunnels == nil {
		cfg.Tunnels = []Tunnel{}
	}
	return cfg, nil
}

// SaveConfig validates and persists the configuration (encrypted). Validation
// runs first so an invalid document is never stored.
func SaveConfig(cfg Config) error {
	if cfg.Tunnels == nil {
		cfg.Tunnels = []Tunnel{}
	}
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	blob, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to encode tunnel config: %w", err)
	}
	return settings.SetSettingEncrypted(settingKeyConfig, string(blob))
}

// ValidateConfig checks every tunnel and cross-tunnel invariants. It also
// rejects listen ports already published by other containers so a tunnel can
// never collide with (or hijack) another service's port.
func ValidateConfig(cfg Config) error {
	external := externalPublishedPorts()
	seenPort := map[int]bool{}
	seenName := map[string]bool{}

	for i, t := range cfg.Tunnels {
		label := t.Name
		if label == "" {
			label = fmt.Sprintf("tunnel #%d", i+1)
		}

		if strings.TrimSpace(t.Name) == "" {
			return fmt.Errorf("%s: name is required", label)
		}
		if seenName[t.Name] {
			return fmt.Errorf("duplicate tunnel name %q", t.Name)
		}
		seenName[t.Name] = true

		if t.ListenPort < 1 || t.ListenPort > 65535 {
			return fmt.Errorf("%s: listen port %d is out of range (1-65535)", label, t.ListenPort)
		}
		if seenPort[t.ListenPort] {
			return fmt.Errorf("%s: listen port %d is used by more than one tunnel", label, t.ListenPort)
		}
		seenPort[t.ListenPort] = true
		if svc, taken := external[t.ListenPort]; taken {
			return fmt.Errorf("%s: port %d is already in use by %s", label, t.ListenPort, svc)
		}

		if strings.TrimSpace(t.User) == "" {
			return fmt.Errorf("%s: username is required", label)
		}
		if !isSafeCredential(t.User) {
			return fmt.Errorf("%s: username must not contain spaces or any of : @ /", label)
		}
		if len(t.Pass) < minPassLen {
			return fmt.Errorf("%s: password must be at least %d characters (every proxy is internet-facing)", label, minPassLen)
		}
		if !isSafeCredential(t.Pass) {
			return fmt.Errorf("%s: password must not contain spaces or any of : @ /", label)
		}

		if t.Upstream.IsSet() {
			if !isSafeCredential(t.Upstream.Host) {
				return fmt.Errorf("%s: upstream host must not contain spaces or any of : @ /", label)
			}
			if t.Upstream.Port < 1 || t.Upstream.Port > 65535 {
				return fmt.Errorf("%s: upstream port %d is out of range (1-65535)", label, t.Upstream.Port)
			}
			if t.Upstream.User != "" && !isSafeCredential(t.Upstream.User) {
				return fmt.Errorf("%s: upstream username must not contain spaces or any of : @ /", label)
			}
			if t.Upstream.Pass != "" && !isSafeCredential(t.Upstream.Pass) {
				return fmt.Errorf("%s: upstream password must not contain spaces or any of : @ /", label)
			}
		}
	}
	return nil
}

// externalPublishedPorts returns host TCP ports currently published by other
// containers (i.e. not our own turbotunnels container), mapped to a descriptive
// label. Used to reject listen-port collisions before saving/starting. A Docker
// API failure yields an empty map — validation then relies on Docker rejecting
// the bind at create time, so this never blocks configuration on a transient
// error.
func externalPublishedPorts() map[int]string {
	resp, err := helper.DockerRequest("GET", "/containers/json", nil)
	if err != nil {
		return map[int]string{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return map[int]string{}
	}

	var containers []struct {
		Names []string `json:"Names"`
		Ports []struct {
			PublicPort int    `json:"PublicPort"`
			Type       string `json:"Type"`
		} `json:"Ports"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return map[int]string{}
	}

	out := map[int]string{}
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		if name == ContainerName {
			continue // our own container — its ports are ours to rebind
		}
		for _, p := range c.Ports {
			if p.Type != "tcp" || p.PublicPort == 0 {
				continue
			}
			label := name
			if label == "" {
				label = "another container"
			}
			out[p.PublicPort] = label
		}
	}
	return out
}

// tunnelsJSON renders the config into the compact JSON contract consumed by the
// container's run.py (via the TUNNELS_JSON env var). Kept deliberately minimal:
// exactly the fields the launcher needs, nothing more.
func (c Config) tunnelsJSON() (string, error) {
	type upstreamOut struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	type tunnelOut struct {
		Port     int          `json:"port"`
		User     string       `json:"user"`
		Pass     string       `json:"pass"`
		Upstream *upstreamOut `json:"upstream,omitempty"`
	}
	out := struct {
		Tunnels []tunnelOut `json:"tunnels"`
	}{Tunnels: []tunnelOut{}}

	for _, t := range c.Tunnels {
		to := tunnelOut{Port: t.ListenPort, User: t.User, Pass: t.Pass}
		if t.Upstream.IsSet() {
			to.Upstream = &upstreamOut{
				Host: t.Upstream.Host,
				Port: t.Upstream.Port,
				User: t.Upstream.User,
				Pass: t.Upstream.Pass,
			}
		}
		out.Tunnels = append(out.Tunnels, to)
	}
	blob, err := json.Marshal(out)
	return string(blob), err
}

// listenPorts returns the host ports every tunnel listens on — the set of ports
// the container must publish and the firewall must allow.
func (c Config) listenPorts() []int {
	ports := make([]int, 0, len(c.Tunnels))
	for _, t := range c.Tunnels {
		ports = append(ports, t.ListenPort)
	}
	return ports
}

// portString is a small helper for building Docker port keys like "3128/tcp".
func portString(p int) string {
	return strconv.Itoa(p) + "/tcp"
}

// firstFreePort returns the first TCP port at or above start that is not
// already published by another container. Used by quick-deploy to pick a port
// without the user having to choose one.
func firstFreePort(start int) int {
	taken := externalPublishedPorts()
	for p := start; p <= 65535; p++ {
		if _, used := taken[p]; !used {
			return p
		}
	}
	return start // pathological fallback; SaveConfig will surface a collision
}
