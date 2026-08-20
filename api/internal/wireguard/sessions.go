package wireguard

import (
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"api/internal/router"
)

// onlineWindow matches enrichPeersWithStatus: a peer is "online" if it has
// handshaked within this window.
const onlineWindow = 3 * time.Minute

// liveStat is the per-peer runtime data parsed from `wg show <iface> dump`.
type liveStat struct {
	handshake time.Time
	endpoint  string
	rx, tx    int64
}

// Session is a currently-connected peer, for the "who's on my VPN" widget.
type Session struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`            // VPN address
	Endpoint      string `json:"endpoint"`      // public ip:port they dial in from
	EndpointIP    string `json:"endpointIp"`    // just the IP, for geo lookup
	LastHandshake string `json:"lastHandshake"` // RFC3339
	Rx            int64  `json:"rx"`            // bytes received from peer
	Tx            int64  `json:"tx"`            // bytes sent to peer
}

// getWgLive parses `wg show <iface> dump` into per-pubkey runtime stats.
// Dump columns per peer line: pubkey, psk, endpoint, allowedIps, handshake,
// rx, tx, keepalive.
func (s *Service) getWgLive() map[string]liveStat {
	live := make(map[string]liveStat)
	out, err := exec.Command("wg", "show", s.config.Interface, "dump").Output()
	if err != nil {
		return live
	}
	for i, line := range strings.Split(string(out), "\n") {
		if i == 0 || line == "" { // first line is the interface itself
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		st := liveStat{}
		if ts, err := strconv.ParseInt(f[4], 10, 64); err == nil && ts > 0 {
			st.handshake = time.Unix(ts, 0)
		}
		if f[2] != "" && f[2] != "(none)" {
			st.endpoint = f[2]
		}
		st.rx, _ = strconv.ParseInt(f[5], 10, 64)
		st.tx, _ = strconv.ParseInt(f[6], 10, 64)
		live[f[0]] = st
	}
	return live
}

// endpointIP strips the trailing :port from a wg endpoint, handling IPv6 in
// brackets (e.g. "[2001:db8::1]:51820").
func endpointIP(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	if i := strings.LastIndex(endpoint, "]"); i != -1 && strings.HasPrefix(endpoint, "[") {
		return endpoint[1:i] // IPv6 in brackets
	}
	if i := strings.LastIndex(endpoint, ":"); i != -1 {
		return endpoint[:i]
	}
	return endpoint
}

// handleGetSessions returns the peers connected right now (handshake within the
// online window), newest handshake first.
// GetActiveSessions returns live WireGuard sessions (peers with a recent handshake),
// newest-first. Shared by the HTTP handler and the WS stats broadcast so the Overview
// "Online now" widget can read them from the push instead of polling.
func (s *Service) GetActiveSessions() []Session {
	live := s.getWgLive()
	now := time.Now()

	sessions := make([]Session, 0, len(live))
	for _, p := range s.peerStore.List() {
		st, ok := live[p.PublicKey]
		if !ok || st.handshake.IsZero() || now.Sub(st.handshake) >= onlineWindow {
			continue
		}
		sessions = append(sessions, Session{
			ID:            p.ID,
			Name:          p.Name,
			IP:            p.IPAddress,
			Endpoint:      st.endpoint,
			EndpointIP:    endpointIP(st.endpoint),
			LastHandshake: st.handshake.UTC().Format(time.RFC3339),
			Rx:            st.rx,
			Tx:            st.tx,
		})
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].LastHandshake > sessions[j].LastHandshake
	})
	return sessions
}

func (s *Service) handleGetSessions(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]any{"sessions": s.GetActiveSessions()})
}
