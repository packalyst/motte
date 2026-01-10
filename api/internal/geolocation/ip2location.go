package geolocation

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"api/internal/helper"

	"github.com/ip2location/ip2location-go/v9"
)

const (
	ip2locationDownloadURL = "https://www.ip2location.com/download"
	// Default templates if not provided
	defaultFileCodeTemplate = "{variant}LITEBIN"
	defaultFileNameTemplate = "IP2LOCATION-LITE-{variant}.BIN"
)

// IP2LocationProvider provides IP geolocation using IP2Location
type IP2LocationProvider struct {
	db               *ip2location.DB
	dataDir          string
	token            string
	variant          string
	filePath         string
	fileCodeTemplate string
	fileNameTemplate string
	mu               sync.RWMutex
}

// NewIP2LocationProvider creates a new IP2Location provider
func NewIP2LocationProvider(dataDir, token, variant, fileCodeTemplate, fileNameTemplate string) *IP2LocationProvider {
	if variant == "" {
		variant = "DB1"
	}
	if fileCodeTemplate == "" {
		fileCodeTemplate = defaultFileCodeTemplate
	}
	if fileNameTemplate == "" {
		fileNameTemplate = defaultFileNameTemplate
	}

	fileName := strings.ReplaceAll(fileNameTemplate, "{variant}", variant)

	return &IP2LocationProvider{
		dataDir:          dataDir,
		token:            token,
		variant:          variant,
		filePath:         filepath.Join(dataDir, fileName),
		fileCodeTemplate: fileCodeTemplate,
		fileNameTemplate: fileNameTemplate,
	}
}

// Name returns the provider name
func (p *IP2LocationProvider) Name() string {
	return "ip2location"
}

// Init initializes the provider by loading the database
func (p *IP2LocationProvider) Init() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if database file exists
	if _, err := os.Stat(p.filePath); os.IsNotExist(err) {
		log.Printf("IP2Location database not found at %s", p.filePath)
		// Try to download if we have a token
		if p.token != "" {
			log.Printf("Attempting to download IP2Location database...")
			if err := p.downloadDB(); err != nil {
				return fmt.Errorf("failed to download database: %v", err)
			}
		} else {
			return fmt.Errorf("database not found and no token configured")
		}
	}

	// Open the database
	db, err := ip2location.OpenDB(p.filePath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	p.db = db
	log.Printf("IP2Location database loaded: %s (variant: %s)", p.filePath, p.variant)

	// Clean up other variant files
	p.cleanupOtherVariants()

	return nil
}

// cleanupOtherVariants removes database files from other variants
func (p *IP2LocationProvider) cleanupOtherVariants() {
	variants := []string{"DB1", "DB3", "DB5", "DB11"}
	for _, v := range variants {
		if v == p.variant {
			continue
		}
		fileName := strings.ReplaceAll(p.fileNameTemplate, "{variant}", v)
		filePath := filepath.Join(p.dataDir, fileName)
		if _, err := os.Stat(filePath); err == nil {
			if err := os.Remove(filePath); err != nil {
				log.Printf("Warning: failed to cleanup old variant file %s: %v", filePath, err)
			} else {
				log.Printf("IP2Location: cleaned up old variant file: %s", filePath)
			}
		}
	}
}

// Lookup performs an IP geolocation lookup
func (p *IP2LocationProvider) Lookup(ipStr string) (*GeoResult, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.db == nil {
		return nil, fmt.Errorf("database not loaded")
	}

	result, err := p.db.Get_all(ipStr)
	if err != nil {
		return nil, fmt.Errorf("lookup failed: %v", err)
	}

	geoResult := &GeoResult{
		IP:          ipStr,
		CountryCode: result.Country_short,
		CountryName: result.Country_long,
		Provider:    "ip2location",
		Extra:       make(map[string]interface{}),
	}

	// Add all available fields to Extra (skip "-", empty, or "not available" messages)
	isValid := func(s string) bool {
		return s != "" && s != "-" && !strings.Contains(s, "unavailable")
	}

	if isValid(result.Region) {
		geoResult.Extra["region"] = result.Region
	}
	if isValid(result.City) {
		geoResult.Extra["city"] = result.City
	}
	if result.Latitude != 0 {
		geoResult.Extra["latitude"] = result.Latitude
	}
	if result.Longitude != 0 {
		geoResult.Extra["longitude"] = result.Longitude
	}
	if isValid(result.Zipcode) {
		geoResult.Extra["zipcode"] = result.Zipcode
	}
	if isValid(result.Timezone) {
		geoResult.Extra["timezone"] = result.Timezone
	}
	if isValid(result.Isp) {
		geoResult.Extra["isp"] = result.Isp
	}
	if isValid(result.Domain) {
		geoResult.Extra["domain"] = result.Domain
	}
	if isValid(result.Usagetype) {
		geoResult.Extra["usage_type"] = result.Usagetype
	}

	// Remove Extra if empty
	if len(geoResult.Extra) == 0 {
		geoResult.Extra = nil
	}

	return geoResult, nil
}

// LookupBulk performs bulk IP lookups
func (p *IP2LocationProvider) LookupBulk(ips []string) map[string]*GeoResult {
	results := make(map[string]*GeoResult)
	for _, ip := range ips {
		if result, err := p.Lookup(ip); err == nil {
			results[ip] = result
		}
	}
	return results
}

// Close closes the database
func (p *IP2LocationProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.db != nil {
		p.db.Close()
		p.db = nil
	}
	return nil
}

// NeedsUpdate checks if the database is older than 30 days
func (p *IP2LocationProvider) NeedsUpdate() bool {
	info, err := os.Stat(p.filePath)
	if err != nil {
		return true
	}
	// IP2Location updates monthly
	return time.Since(info.ModTime()) > 30*24*time.Hour
}

// Update downloads a fresh copy of the database
func (p *IP2LocationProvider) Update() error {
	if p.token == "" {
		return fmt.Errorf("no token configured")
	}

	// Download to temp file
	tempPath := p.filePath + ".tmp"
	if err := p.downloadDBToPath(tempPath); err != nil {
		os.Remove(tempPath)
		return err
	}

	// Validate the new database
	testDB, err := ip2location.OpenDB(tempPath)
	if err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("downloaded database is invalid: %v", err)
	}
	testDB.Close()

	// Hot-reload: swap the database
	return p.hotReload(tempPath)
}

// hotReload atomically swaps the database file and reloads
func (p *IP2LocationProvider) hotReload(newPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Open new database before closing old one
	newDB, err := ip2location.OpenDB(newPath)
	if err != nil {
		return fmt.Errorf("failed to open new database: %v", err)
	}

	// Close old database
	if p.db != nil {
		p.db.Close()
	}

	// Atomic rename
	if err := os.Rename(newPath, p.filePath); err != nil {
		newDB.Close()
		return fmt.Errorf("failed to rename database: %v", err)
	}

	// Swap databases
	p.db = newDB
	log.Printf("IP2Location database hot-reloaded successfully")
	return nil
}

// LastUpdated returns the modification time of the database file
func (p *IP2LocationProvider) LastUpdated() time.Time {
	info, err := os.Stat(p.filePath)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// IsAvailable returns whether the provider is ready for lookups
func (p *IP2LocationProvider) IsAvailable() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.db != nil
}

// downloadDB downloads the database to the default path
func (p *IP2LocationProvider) downloadDB() error {
	return p.downloadDBToPath(p.filePath)
}

// downloadDBToPath downloads the IP2Location database
func (p *IP2LocationProvider) downloadDBToPath(destPath string) error {
	// Build file code from template
	fileCode := strings.ReplaceAll(p.fileCodeTemplate, "{variant}", p.variant)

	// Build download URL
	url := fmt.Sprintf("%s/?token=%s&file=%s", ip2locationDownloadURL, p.token, fileCode)

	log.Printf("Downloading IP2Location database (variant: %s)...", p.variant)

	client := &http.Client{Timeout: helper.GeoDBDownloadTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed: HTTP %d - %s", resp.StatusCode, string(body))
	}

	// Save to temp zip file
	zipPath := destPath + ".zip"
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %v", err)
	}

	_, err = io.Copy(zipFile, resp.Body)
	zipFile.Close()
	if err != nil {
		os.Remove(zipPath)
		return fmt.Errorf("failed to download zip: %v", err)
	}

	// Extract .BIN file from zip
	if err := p.extractBINFromZip(zipPath, destPath); err != nil {
		os.Remove(zipPath)
		return err
	}

	os.Remove(zipPath)
	log.Printf("IP2Location database downloaded: %s", destPath)
	return nil
}

// extractBINFromZip extracts the .BIN file from the downloaded zip
func (p *IP2LocationProvider) extractBINFromZip(zipPath, destPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %v", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		if strings.HasSuffix(strings.ToUpper(file.Name), ".BIN") {
			src, err := file.Open()
			if err != nil {
				return fmt.Errorf("failed to open file in zip: %v", err)
			}
			defer src.Close()

			dst, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %v", err)
			}

			_, err = io.Copy(dst, src)
			dst.Close()
			if err != nil {
				os.Remove(destPath)
				return fmt.Errorf("failed to extract file: %v", err)
			}

			return nil
		}
	}

	return fmt.Errorf("no .BIN file found in zip")
}

// SetToken updates the download token
func (p *IP2LocationProvider) SetToken(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.token = token
}

// SetVariant updates the database variant and cleans up the old one
func (p *IP2LocationProvider) SetVariant(variant string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Skip if variant unchanged
	if p.variant == variant {
		return
	}

	oldFilePath := p.filePath

	// Close current database
	if p.db != nil {
		p.db.Close()
		p.db = nil
	}

	// Update to new variant
	p.variant = variant
	fileName := strings.ReplaceAll(p.fileNameTemplate, "{variant}", variant)
	p.filePath = filepath.Join(p.dataDir, fileName)

	// Delete old variant file if it exists
	if oldFilePath != p.filePath {
		if _, err := os.Stat(oldFilePath); err == nil {
			os.Remove(oldFilePath)
			log.Printf("IP2Location: cleaned up old variant file: %s", oldFilePath)
		}
	}
}

// GetFileSize returns the size of the database file
func (p *IP2LocationProvider) GetFileSize() int64 {
	info, err := os.Stat(p.filePath)
	if err != nil {
		return 0
	}
	return info.Size()
}

// GetFilePath returns the database file path
func (p *IP2LocationProvider) GetFilePath() string {
	return p.filePath
}

// GetVariant returns the current database variant
func (p *IP2LocationProvider) GetVariant() string {
	return p.variant
}
