package turbotunnels

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"api/internal/helper"
	"api/internal/settings"
)

// defaultTunnelsJSON mirrors turbotunnels/tunnels.default.json — the config the
// container falls back to when TUNNELS_JSON is not set. Kept here so the panel
// can display the same tunnels the container will run.
const defaultTunnelsJSON = `{"tunnels":[{"listen_url":"http://","listen_user":"${PROXY_USER}","listen_pass":"${PROXY_PASS}","host_ip":"${HOST_IP}","listen_port":3128,"tunnel_url":"tcp://","tunnel_ip":"","tunnel_port":""}]}`

// Settings keys under which the generated credentials are persisted, so they
// stay stable across restarts and can be shown in the UI.
const (
	keyProxyUser = "turbotunnels_proxy_user"
	keyProxyPass = "turbotunnels_proxy_pass"
	keyAdminUser = "turbotunnels_admin_user"
	keyAdminPass = "turbotunnels_admin_pass"
)

// Credentials are the generated proxy (client-facing) + control-API creds.
type Credentials struct {
	ProxyUser string `json:"proxyUser"`
	ProxyPass string `json:"proxyPass"`
	AdminUser string `json:"adminUser"`
	AdminPass string `json:"adminPass"`
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "changeme"
	}
	return hex.EncodeToString(b)
}

// ensureCredentials returns stored credentials, generating and persisting them
// on first use so the container never runs with a default/known password.
func ensureCredentials() Credentials {
	get := func(key, prefix string, n int) string {
		if v, err := settings.GetSetting(key); err == nil && v != "" {
			return v
		}
		v := prefix + randHex(n)
		_ = settings.SetSetting(key, v)
		return v
	}
	return Credentials{
		ProxyUser: get(keyProxyUser, "proxy_", 3),
		ProxyPass: get(keyProxyPass, "", 12),
		AdminUser: get(keyAdminUser, "admin_", 3),
		AdminPass: get(keyAdminPass, "", 12),
	}
}

// TunnelInfo describes one exposed proxy endpoint plus a ready-to-use command.
type TunnelInfo struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Command  string `json:"command"`
}

// tunnelDefField pulls a string field from a raw tunnel map, coercing numbers.
func tunnelDefField(m map[string]interface{}, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return strconv.Itoa(int(v))
	}
	return ""
}

// expandCred resolves ${PROXY_USER}/${PROXY_PASS} to the generated values and
// any other ${VAR} to the environment, so a config's real credentials show up
// whether they are placeholders or hardcoded.
func expandCred(s string, creds Credentials) string {
	return os.Expand(s, func(k string) string {
		switch k {
		case "PROXY_USER":
			return creds.ProxyUser
		case "PROXY_PASS":
			return creds.ProxyPass
		default:
			return os.Getenv(k)
		}
	})
}

// tunnelList parses the ACTUAL tunnel config (TUNNELS_JSON if set, else the
// baked default) and reports each proxy endpoint with its real credentials.
// Generated creds only appear where the config uses ${PROXY_USER}/${PROXY_PASS}.
func tunnelList(creds Credentials) []TunnelInfo {
	host := helper.GetEnvOptional("SERVER_IP", "<server-ip>")

	raw := strings.TrimSpace(helper.GetEnvOptional("TUNNELS_JSON", ""))
	if raw == "" {
		raw = defaultTunnelsJSON
	}
	var cfg struct {
		Tunnels []map[string]interface{} `json:"tunnels"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil
	}

	out := []TunnelInfo{}
	for _, m := range cfg.Tunnels {
		proto := strings.TrimSuffix(tunnelDefField(m, "listen_url"), "://")
		if proto == "" {
			proto = "http"
		}
		port, _ := strconv.Atoi(tunnelDefField(m, "listen_port"))
		user := expandCred(tunnelDefField(m, "listen_user"), creds)
		pass := expandCred(tunnelDefField(m, "listen_pass"), creds)

		authPrefix := ""
		if user != "" {
			authPrefix = user + ":" + pass + "@"
		}
		out = append(out, TunnelInfo{
			Protocol: proto,
			Host:     host,
			Port:     port,
			User:     user,
			Pass:     pass,
			Command:  fmt.Sprintf("curl -x %s://%s%s:%d https://ifconfig.me", proto, authPrefix, host, port),
		})
	}
	return out
}
