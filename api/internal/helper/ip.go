package helper

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

var (
	trustedProxyCIDRs []*net.IPNet
	trustedProxyMutex sync.RWMutex
)

// InitTrustedProxies initializes the list of trusted proxy CIDRs
// Pass comma-separated CIDR list, e.g. "172.18.0.0/24,10.0.0.0/8"
func InitTrustedProxies(cidrs string) {
	trustedProxyMutex.Lock()
	defer trustedProxyMutex.Unlock()

	trustedProxyCIDRs = nil
	if cidrs == "" {
		return
	}

	for _, cidrStr := range strings.Split(cidrs, ",") {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, cidr)
	}
}

// IsTrustedProxy checks if an IP is in the trusted proxy list
func IsTrustedProxy(ipStr string) bool {
	trustedProxyMutex.RLock()
	defer trustedProxyMutex.RUnlock()

	if len(trustedProxyCIDRs) == 0 {
		return true // No trusted proxies configured = trust all
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// GetClientIP extracts the real client IP from an HTTP request
// Checks headers in order: CF-Connecting-IP, X-Forwarded-For, X-Real-IP, RemoteAddr
func GetClientIP(r *http.Request) string {
	// Extract remote IP (without port)
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	// Only trust proxy headers from trusted proxies
	if IsTrustedProxy(remoteIP) {
		// CF-Connecting-IP (Cloudflare - most reliable)
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return strings.TrimSpace(cfIP)
		}

		// X-Forwarded-For (standard proxy header)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP (original client)
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}

		// X-Real-IP (nginx)
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	return remoteIP
}
