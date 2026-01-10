package geolocation

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"api/internal/helper"

	"github.com/oschwald/maxminddb-golang"
)

const (
	maxmindDownloadURL = "https://download.maxmind.com/app/geoip_download"
	maxmindEdition     = "GeoLite2-Country"
	maxmindDBFile      = "GeoLite2-Country.mmdb"
)

// MaxMindProvider provides IP geolocation using MaxMind GeoLite2
type MaxMindProvider struct {
	reader     *maxminddb.Reader
	dataDir    string
	licenseKey string
	filePath   string
	mu         sync.RWMutex
}

// maxmindRecord represents the structure of MaxMind country data
type maxmindRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
}

// NewMaxMindProvider creates a new MaxMind provider
func NewMaxMindProvider(dataDir, licenseKey string) *MaxMindProvider {
	return &MaxMindProvider{
		dataDir:    dataDir,
		licenseKey: licenseKey,
		filePath:   filepath.Join(dataDir, maxmindDBFile),
	}
}

// Name returns the provider name
func (p *MaxMindProvider) Name() string {
	return "maxmind"
}

// Init initializes the provider by loading the database
func (p *MaxMindProvider) Init() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if database file exists
	if _, err := os.Stat(p.filePath); os.IsNotExist(err) {
		log.Printf("MaxMind database not found at %s", p.filePath)
		// Try to download if we have a license key
		if p.licenseKey != "" {
			log.Printf("Attempting to download MaxMind database...")
			if err := p.downloadDB(); err != nil {
				return fmt.Errorf("failed to download database: %v", err)
			}
		} else {
			return fmt.Errorf("database not found and no license key configured")
		}
	}

	// Open the database
	reader, err := maxminddb.Open(p.filePath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	p.reader = reader
	log.Printf("MaxMind database loaded: %s", p.filePath)
	return nil
}

// Lookup performs an IP geolocation lookup
func (p *MaxMindProvider) Lookup(ipStr string) (*GeoResult, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.reader == nil {
		return nil, fmt.Errorf("database not loaded")
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	var record maxmindRecord
	err := p.reader.Lookup(ip, &record)
	if err != nil {
		return nil, fmt.Errorf("lookup failed: %v", err)
	}

	// Prefer country over registered_country
	countryCode := record.Country.ISOCode
	countryName := record.Country.Names["en"]
	if countryCode == "" {
		countryCode = record.RegisteredCountry.ISOCode
		countryName = record.RegisteredCountry.Names["en"]
	}

	return &GeoResult{
		IP:          ipStr,
		CountryCode: countryCode,
		CountryName: countryName,
		Provider:    "maxmind",
	}, nil
}

// LookupBulk performs bulk IP lookups
func (p *MaxMindProvider) LookupBulk(ips []string) map[string]*GeoResult {
	results := make(map[string]*GeoResult)
	for _, ip := range ips {
		if result, err := p.Lookup(ip); err == nil {
			results[ip] = result
		}
	}
	return results
}

// Close closes the database reader
func (p *MaxMindProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.reader != nil {
		err := p.reader.Close()
		p.reader = nil
		return err
	}
	return nil
}

// NeedsUpdate checks if the database is older than 7 days
func (p *MaxMindProvider) NeedsUpdate() bool {
	info, err := os.Stat(p.filePath)
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) > 7*24*time.Hour
}

// Update downloads a fresh copy of the database
func (p *MaxMindProvider) Update() error {
	if p.licenseKey == "" {
		return fmt.Errorf("no license key configured")
	}

	// Download to temp file
	tempPath := p.filePath + ".tmp"
	if err := p.downloadDBToPath(tempPath); err != nil {
		os.Remove(tempPath)
		return err
	}

	// Validate the new database
	testReader, err := maxminddb.Open(tempPath)
	if err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("downloaded database is invalid: %v", err)
	}
	testReader.Close()

	// Hot-reload: swap the database
	return p.hotReload(tempPath)
}

// hotReload atomically swaps the database file and reloads
func (p *MaxMindProvider) hotReload(newPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Open new reader before closing old one
	newReader, err := maxminddb.Open(newPath)
	if err != nil {
		return fmt.Errorf("failed to open new database: %v", err)
	}

	// Close old reader
	if p.reader != nil {
		p.reader.Close()
	}

	// Atomic rename
	if err := os.Rename(newPath, p.filePath); err != nil {
		newReader.Close()
		return fmt.Errorf("failed to rename database: %v", err)
	}

	// Swap readers
	p.reader = newReader
	log.Printf("MaxMind database hot-reloaded successfully")
	return nil
}

// LastUpdated returns the modification time of the database file
func (p *MaxMindProvider) LastUpdated() time.Time {
	info, err := os.Stat(p.filePath)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// IsAvailable returns whether the provider is ready for lookups
func (p *MaxMindProvider) IsAvailable() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.reader != nil
}

// downloadDB downloads the database to the default path
func (p *MaxMindProvider) downloadDB() error {
	return p.downloadDBToPath(p.filePath)
}

// downloadDBToPath downloads the MaxMind database
func (p *MaxMindProvider) downloadDBToPath(destPath string) error {
	// Build download URL
	url := fmt.Sprintf("%s?edition_id=%s&license_key=%s&suffix=tar.gz",
		maxmindDownloadURL, maxmindEdition, p.licenseKey)

	log.Printf("Downloading MaxMind database...")

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

	// Extract .mmdb from tar.gz
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %v", err)
		}

		// Look for the .mmdb file
		if strings.HasSuffix(header.Name, ".mmdb") {
			outFile, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %v", err)
			}

			_, err = io.Copy(outFile, tarReader)
			outFile.Close()
			if err != nil {
				os.Remove(destPath)
				return fmt.Errorf("failed to write database: %v", err)
			}

			log.Printf("MaxMind database downloaded: %s", destPath)
			return nil
		}
	}

	return fmt.Errorf("no .mmdb file found in archive")
}

// SetLicenseKey updates the license key
func (p *MaxMindProvider) SetLicenseKey(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.licenseKey = key
}

// GetFileSize returns the size of the database file
func (p *MaxMindProvider) GetFileSize() int64 {
	info, err := os.Stat(p.filePath)
	if err != nil {
		return 0
	}
	return info.Size()
}

// GetFilePath returns the database file path
func (p *MaxMindProvider) GetFilePath() string {
	return p.filePath
}
