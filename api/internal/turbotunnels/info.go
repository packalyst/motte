package turbotunnels

import (
	"fmt"
	"strings"

	"api/internal/helper"
)

// EndpointInfo is one listener's public endpoint + a ready-to-paste command.
type EndpointInfo struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Command  string `json:"command"`
}

// WebhookInfo is one webhook's public trigger URL (with its keys) for the UI.
type WebhookInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Method     string `json:"method"`
	TriggerURL string `json:"triggerUrl"` // public URL to trigger it (contains the keys)
}

// TunnelInfo describes one configured proxy for the UI: shared identity plus one
// endpoint per listener (HTTP and/or SOCKS5).
type TunnelInfo struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Host          string         `json:"host"`
	User          string         `json:"user"`
	Pass          string         `json:"pass"`
	Direct        bool           `json:"direct"`        // true = exits this server; false = chained
	RotateTrigger string         `json:"rotateTrigger"` // public URL to trigger rotation (has the key)
	Endpoints     []EndpointInfo `json:"endpoints"`
	Webhooks      []WebhookInfo  `json:"webhooks"`
}

// proxyHost is the hostname shown in tunnel commands: the configured PROXY_DOMAIN
// if set, otherwise the server's public IP.
func proxyHost() string {
	if d := helper.GetEnvOptional("PROXY_DOMAIN", ""); d != "" {
		return d
	}
	return helper.GetEnvOptional("SERVER_IP", "<server-ip>")
}

// rotateBaseURL is the HTTPS base for the public rotation trigger. Prefer the
// proxy domain (manage.sh gives it a Traefik /api/restart route + cert), else
// the panel's SSL domain (which already routes /api/ and has a cert), else the
// server IP.
func rotateBaseURL() string {
	if d := helper.GetEnvOptional("PROXY_DOMAIN", ""); d != "" {
		return "https://" + d
	}
	if d := helper.GetEnvOptional("SSL_DOMAIN", ""); d != "" {
		return "https://" + d
	}
	return "http://" + helper.GetEnvOptional("SERVER_IP", "<server-ip>")
}

// tunnelInfos builds the UI view of every configured tunnel. The host is the
// proxy domain (or server IP) so the example commands are copy-paste ready.
func tunnelInfos(cfg Config) []TunnelInfo {
	host := proxyHost()
	out := make([]TunnelInfo, 0, len(cfg.Tunnels))
	for _, t := range cfg.Tunnels {
		auth := ""
		if t.User != "" {
			auth = t.User + ":" + t.Pass + "@"
		}
		eps := make([]EndpointInfo, 0, len(t.Listeners))
		for _, l := range t.Listeners {
			// curl proxy scheme: http:// for HTTP, socks5h:// for SOCKS5 (the
			// "h" resolves DNS through the proxy).
			scheme := "http"
			if l.Proto() == "socks5" {
				scheme = "socks5h"
			}
			eps = append(eps, EndpointInfo{
				Protocol: l.Proto(),
				Port:     l.Port,
				Command:  fmt.Sprintf("curl -x %s://%s%s:%d https://ifconfig.me", scheme, auth, host, l.Port),
			})
		}
		// Public rotation trigger URL (only meaningful once a provider rotateUrl
		// is set; shown whenever the tunnel has a key). The provider URL itself
		// is never exposed.
		rotateTrigger := ""
		if t.RotateKey != "" && t.RotateURL != "" {
			rotateTrigger = rotateBaseURL() + "/api/restart/" + t.RotateKey
		}
		whs := make([]WebhookInfo, 0, len(t.Webhooks))
		for _, wh := range t.Webhooks {
			trigger := ""
			if len(wh.Keys) > 0 {
				trigger = rotateBaseURL() + "/api/hook/" + strings.Join(wh.Keys, "/")
			}
			whs = append(whs, WebhookInfo{
				ID:         wh.ID,
				Name:       wh.Name,
				Method:     wh.Method,
				TriggerURL: trigger,
			})
		}
		out = append(out, TunnelInfo{
			ID:            t.ID,
			Name:          t.Name,
			Host:          host,
			User:          t.User,
			Pass:          t.Pass,
			Direct:        t.IsDirect(),
			RotateTrigger: rotateTrigger,
			Endpoints:     eps,
			Webhooks:      whs,
		})
	}
	return out
}
