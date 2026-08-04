package turbotunnels

import (
	"fmt"

	"api/internal/helper"
)

// EndpointInfo is one listener's public endpoint + a ready-to-paste command.
type EndpointInfo struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Command  string `json:"command"`
}

// TunnelInfo describes one configured proxy for the UI: shared identity plus one
// endpoint per listener (HTTP and/or SOCKS5).
type TunnelInfo struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Host      string         `json:"host"`
	User      string         `json:"user"`
	Pass      string         `json:"pass"`
	Direct    bool           `json:"direct"` // true = exits this server; false = chained
	RotateURL string         `json:"rotateUrl"`
	Endpoints []EndpointInfo `json:"endpoints"`
}

// tunnelInfos builds the UI view of every configured tunnel. The host is the
// server's public IP so the example commands are copy-paste ready.
func tunnelInfos(cfg Config) []TunnelInfo {
	host := helper.GetEnvOptional("SERVER_IP", "<server-ip>")
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
		out = append(out, TunnelInfo{
			ID:        t.ID,
			Name:      t.Name,
			Host:      host,
			User:      t.User,
			Pass:      t.Pass,
			Direct:    t.IsDirect(),
			RotateURL: t.RotateURL,
			Endpoints: eps,
		})
	}
	return out
}
