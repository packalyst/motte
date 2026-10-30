package firewall

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"api/internal/helper"
	"api/internal/nftables"
)

// Port 80 gate (Traefik's sentinel "gate"). While Cloudflare-only is on, the kernel no longer
// filters port 80 (Let's Encrypt must reach it from addresses it doesn't publish); Traefik admits
// only Cloudflare and the panel's own networks there, plus ACME challenge requests, and drops
// anyone else silently. The panel feeds it the list and receives its drops, which the 'webgate'
// jail turns into bans.

// webGateDropMarker starts each line of the jail file; the jail's pattern matches it.
const webGateDropMarker = "WEBGATE_DROP SRC="

// HandleInternalWebGate serves who may use port 80: "off" when Cloudflare-only is off (everyone
// may), else "on" followed by one CIDR per line (Cloudflare's ranges and the trusted admin
// sources, the same ones the kernel lets reach 443). Internal-only, like the block list.
func (s *Service) HandleInternalWebGate(w http.ResponseWriter, r *http.Request) {
	if !internalCallerAllowed(r) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	sources := nftables.NewCloudflareOnlyTable(s.db).WebGateSources()
	if sources == nil {
		w.Write([]byte("off\n"))
		return
	}
	w.Write([]byte("on\n" + strings.Join(sources, "\n") + "\n"))
}

// HandleInternalWebGateDrops records the gate's dropped addresses ("ip count" per line) in the
// 'webgate' jail's file (from Traefik only, like every /internal/* endpoint). Public IPv4
// addresses only (the jail and the firewall ban IPv4; private and VPN sources are never gated).
func (s *Service) HandleInternalWebGateDrops(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !internalCallerAllowed(r) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var lines []string
	sc := bufio.NewScanner(io.LimitReader(r.Body, helper.MaxWebGateReportBytes))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		ip := net.ParseIP(f[0]).To4()
		n, err := strconv.Atoi(f[1])
		if ip == nil || err != nil || n < 1 || helper.IsNonPublicIP(ip) {
			continue
		}
		for i := 0; i < min(n, helper.MaxWebGateDropsPerIP); i++ {
			lines = append(lines, webGateDropMarker+ip.String())
		}
	}
	if err := helper.AppendJailLines(helper.WebGateLogPath(), lines); err != nil {
		log.Printf("webgate: cannot write the jail file: %v", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ensureWebGateLog creates the jail's file, so its monitor finds it at boot (a jail whose file is
// missing at startup is skipped).
func ensureWebGateLog() {
	f, err := os.OpenFile(helper.WebGateLogPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		log.Printf("webgate: cannot create the jail file: %v", err)
		return
	}
	f.Close()
}
