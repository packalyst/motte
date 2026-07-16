package turbotunnels

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"api/internal/helper"
	"api/internal/settings"
)

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

// tunnelList returns the proxy endpoints turbotunnels exposes with the current
// credentials. The default config is a single direct HTTP proxy on 3128.
func tunnelList(creds Credentials) []TunnelInfo {
	host := helper.GetEnvOptional("SERVER_IP", "<server-ip>")
	return []TunnelInfo{
		{
			Protocol: "http",
			Host:     host,
			Port:     3128,
			User:     creds.ProxyUser,
			Pass:     creds.ProxyPass,
			Command:  fmt.Sprintf("curl -x http://%s:%s@%s:3128 https://ifconfig.me", creds.ProxyUser, creds.ProxyPass, host),
		},
	}
}
