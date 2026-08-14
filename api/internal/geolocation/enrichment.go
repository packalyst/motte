package geolocation

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"api/internal/helper"
	"api/internal/router"
)

const (
	// Download/extract caps. Real IP2Location LITE CSV zips are tens of MB; the caps are
	// generous backstops so a hostile or misconfigured source can't exhaust disk/memory.
	maxEnrichmentDownloadBytes = 300 << 20 // 300 MB (compressed download)
	maxEnrichmentExtractBytes  = 800 << 20 // 800 MB (uncompressed CSV — zip-bomb guard)

	// Default IP2Location LITE download codes for the IPv6 CSV variants (which include
	// IPv4). Overridable per deployment in configs/geolocation.json if IP2Location
	// changes them.
	defaultASNFileCode   = "DBASNLITEIPV6"
	defaultProxyFileCode = "PX1LITECSVIPV6"

	ip2locationDownloadBase = "https://www.ip2location.com/download"
)

// EnrichmentDBStatus is the on-disk + in-memory state of one enrichment DB.
type EnrichmentDBStatus struct {
	Available  bool   `json:"available"`   // file present on disk
	Loaded     bool   `json:"loaded"`      // table loaded in memory
	Ranges     int    `json:"ranges"`      // number of ranges loaded
	FileSize   int64  `json:"file_size"`   // bytes on disk
	LastUpdate string `json:"last_update"` // file mtime
}

// EnrichmentStatus reports both enrichment DBs.
type EnrichmentStatus struct {
	ASN   EnrichmentDBStatus `json:"asn"`
	Proxy EnrichmentDBStatus `json:"proxy"`
}

// enrichmentFileCode returns the configured (or default) IP2Location download code.
func (s *Service) enrichmentFileCode(which string) string {
	cfg := s.providersConfig.Providers["ip2location"]
	switch which {
	case "asn":
		if cfg.ASNFileCode != "" {
			return cfg.ASNFileCode
		}
		return defaultASNFileCode
	case "proxy":
		// Prefer the tier template (PX{variant}LITECSVIPV6) with the selected tier.
		if cfg.ProxyFileCodeTemplate != "" {
			s.mu.RLock()
			variant := s.config.IP2ProxyVariant
			s.mu.RUnlock()
			// Whitelist the tier (PX1–PX12) before it reaches the download URL; an
			// out-of-range value falls back to the default rather than producing a
			// malformed file= query parameter.
			if !validProxyVariant(variant) {
				variant = "12"
			}
			return strings.ReplaceAll(cfg.ProxyFileCodeTemplate, "{variant}", variant)
		}
		if cfg.ProxyFileCode != "" {
			return cfg.ProxyFileCode
		}
		return defaultProxyFileCode
	}
	return ""
}

// validProxyVariant reports whether v is a supported IP2Proxy tier ("1".."12").
func validProxyVariant(v string) bool {
	switch v {
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12":
		return true
	}
	return false
}

// proxyColumnsFromConfig reads the configurable CSV column indices for the richer
// proxy fields, defaulting to the standard IP2Proxy layout when unset.
func (s *Service) proxyColumnsFromConfig() proxyColumns {
	c := proxyColumns{usageType: 9, threat: 13, fraud: 14}
	if m := s.providersConfig.Providers["ip2location"].ProxyColumns; m != nil {
		if v, ok := m["usage_type"]; ok {
			c.usageType = v
		}
		if v, ok := m["threat"]; ok {
			c.threat = v
		}
		if v, ok := m["fraud_score"]; ok {
			c.fraud = v
		}
	}
	return c
}

// downloadEnrichmentCSV fetches an IP2Location LITE zip by file code and extracts its
// CSV to destPath. Both the download and the extraction are size-capped. The remote
// host is fixed (no SSRF), the token comes from encrypted settings, and destPath is a
// fixed path under the data dir (no traversal).
func (s *Service) downloadEnrichmentCSV(fileCode, destPath string) error {
	s.mu.RLock()
	token := s.config.IP2LocationToken
	s.mu.RUnlock()
	if token == "" {
		return fmt.Errorf("IP2Location token is not configured")
	}
	if fileCode == "" {
		return fmt.Errorf("download code is not configured")
	}

	url := fmt.Sprintf("%s/?token=%s&file=%s", ip2locationDownloadBase, token, fileCode)
	client := &http.Client{Timeout: helper.GeoDBDownloadTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d (check the token and file code %q)", resp.StatusCode, fileCode)
	}

	zipPath := destPath + ".zip"
	zf, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	n, err := io.Copy(zf, io.LimitReader(resp.Body, maxEnrichmentDownloadBytes+1))
	zf.Close()
	if err != nil {
		os.Remove(zipPath)
		return fmt.Errorf("download failed: %v", err)
	}
	if n > maxEnrichmentDownloadBytes {
		os.Remove(zipPath)
		return fmt.Errorf("download exceeds %d bytes", maxEnrichmentDownloadBytes)
	}

	if err := extractFirstCSV(zipPath, destPath); err != nil {
		os.Remove(zipPath)
		return err
	}
	os.Remove(zipPath)
	return nil
}

// extractFirstCSV writes the first .CSV entry in the zip to destPath, capping the
// uncompressed size to guard against a zip bomb.
func extractFirstCSV(zipPath, destPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %v", err)
	}
	defer reader.Close()

	for _, f := range reader.File {
		if !strings.HasSuffix(strings.ToUpper(f.Name), ".CSV") {
			continue
		}
		src, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to open CSV in zip: %v", err)
		}
		dst, err := os.Create(destPath)
		if err != nil {
			src.Close()
			return fmt.Errorf("failed to create output file: %v", err)
		}
		written, err := io.Copy(dst, io.LimitReader(src, maxEnrichmentExtractBytes+1))
		dst.Close()
		src.Close()
		if err != nil {
			os.Remove(destPath)
			return fmt.Errorf("failed to extract CSV: %v", err)
		}
		if written > maxEnrichmentExtractBytes {
			os.Remove(destPath)
			return fmt.Errorf("extracted CSV exceeds %d bytes", maxEnrichmentExtractBytes)
		}
		return nil
	}
	return fmt.Errorf("no .CSV file found in the downloaded archive")
}

// enrichmentStatus reports both enrichment DBs (disk + memory).
func (s *Service) enrichmentStatus() EnrichmentStatus {
	s.mu.RLock()
	asnDB, proxyDB := s.asnDB, s.proxyDB
	s.mu.RUnlock()

	stat := func(path string, tbl interface{ count() int }, loaded bool) EnrichmentDBStatus {
		st := EnrichmentDBStatus{Loaded: loaded}
		if loaded {
			st.Ranges = tbl.count()
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			st.Available = true
			st.FileSize = info.Size()
			st.LastUpdate = info.ModTime().Format("2006-01-02 15:04:05")
		}
		return st
	}

	return EnrichmentStatus{
		ASN:   stat(s.asnDBPath(), asnDB, asnDB != nil),
		Proxy: stat(s.proxyDBPath(), proxyDB, proxyDB != nil),
	}
}

// disableEnrichment removes an enrichment DB from disk and drops its in-memory table.
// Used when its toggle is turned off.
func (s *Service) disableEnrichment(db string) {
	var path string
	switch db {
	case "asn":
		path = s.asnDBPath()
	case "proxy":
		path = s.proxyDBPath()
	default:
		return
	}
	os.Remove(path)
	s.mu.Lock()
	if db == "asn" {
		s.asnDB = nil
	} else {
		s.proxyDB = nil
	}
	s.mu.Unlock()
}

// handleGetEnrichmentStatus  GET /api/geo/enrichment
func (s *Service) handleGetEnrichmentStatus(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, s.enrichmentStatus())
}

// handleDownloadEnrichment  POST /api/geo/enrichment/download?db=asn|proxy
func (s *Service) handleDownloadEnrichment(w http.ResponseWriter, r *http.Request) {
	db := r.URL.Query().Get("db")
	var destPath string
	switch db {
	case "asn":
		destPath = s.asnDBPath()
	case "proxy":
		destPath = s.proxyDBPath()
	default:
		router.JSONError(w, "db must be 'asn' or 'proxy'", http.StatusBadRequest)
		return
	}

	if err := s.downloadEnrichmentCSV(s.enrichmentFileCode(db), destPath); err != nil {
		router.JSONError(w, err.Error(), http.StatusFailedDependency)
		return
	}
	s.loadEnrichmentDBs() // reload the fresh file into memory (atomic swap)
	router.JSON(w, s.enrichmentStatus())
}

// handleDeleteEnrichment  DELETE /api/geo/enrichment?db=asn|proxy
func (s *Service) handleDeleteEnrichment(w http.ResponseWriter, r *http.Request) {
	db := r.URL.Query().Get("db")
	var path string
	switch db {
	case "asn":
		path = s.asnDBPath()
	case "proxy":
		path = s.proxyDBPath()
	default:
		router.JSONError(w, "db must be 'asn' or 'proxy'", http.StatusBadRequest)
		return
	}
	os.Remove(path)
	// Drop the in-memory table too.
	s.mu.Lock()
	if db == "asn" {
		s.asnDB = nil
	} else {
		s.proxyDB = nil
	}
	s.mu.Unlock()
	router.JSON(w, s.enrichmentStatus())
}
