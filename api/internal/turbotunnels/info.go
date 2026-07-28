package turbotunnels

import (
	"fmt"

	"api/internal/helper"
)

// TunnelInfo describes one configured proxy for the UI: its public endpoint,
// credentials, mode, and a ready-to-paste example command.
type TunnelInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Direct   bool   `json:"direct"` // true = exits this server; false = chained upstream
	Command  string `json:"command"`
}

// tunnelInfos builds the UI view of every configured tunnel. The host is the
// server's public IP so the example command is copy-paste ready.
func tunnelInfos(cfg Config) []TunnelInfo {
	host := helper.GetEnvOptional("SERVER_IP", "<server-ip>")
	out := make([]TunnelInfo, 0, len(cfg.Tunnels))
	for _, t := range cfg.Tunnels {
		auth := ""
		if t.User != "" {
			auth = t.User + ":" + t.Pass + "@"
		}
		out = append(out, TunnelInfo{
			ID:       t.ID,
			Name:     t.Name,
			Protocol: "http",
			Host:     host,
			Port:     t.ListenPort,
			User:     t.User,
			Pass:     t.Pass,
			Direct:   t.IsDirect(),
			Command:  fmt.Sprintf("curl -x http://%s%s:%d https://ifconfig.me", auth, host, t.ListenPort),
		})
	}
	return out
}
