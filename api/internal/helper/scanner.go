package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// PortResult represents a discovered open port
type PortResult struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// ScanProgress represents the current scan progress
type ScanProgress struct {
	Total     int  `json:"total"`
	Scanned   int  `json:"scanned"`
	Found     int  `json:"found"`
	Completed bool `json:"completed"`
}

// ScanConfig holds scanner configuration
type ScanConfig struct {
	PortStart  int
	PortEnd    int
	Concurrent int
	PauseMs    int
	TimeoutMs  int
}

// CommonPort represents a port from the common-ports.json config
type CommonPort struct {
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Category string `json:"category"`
}

type commonPortsConfig struct {
	Description string       `json:"description"`
	Ports       []CommonPort `json:"ports"`
}

var (
	commonPorts     []CommonPort
	commonPortsOnce sync.Once
)

// LoadCommonPorts loads the common ports from config file (thread-safe)
func LoadCommonPorts() []CommonPort {
	commonPortsOnce.Do(func() {
		paths := []string{CommonPortsConfigPath, "configs/common-ports.json"}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var config commonPortsConfig
			if err := json.Unmarshal(data, &config); err == nil {
				commonPorts = config.Ports
				return
			}
		}
	})
	return commonPorts
}

// GetCommonPorts returns the list of common ports
func GetCommonPorts() []CommonPort {
	return LoadCommonPorts()
}

// waitWithTimeout waits for WaitGroup with a timeout, returns true if completed
func waitWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// ScanPorts scans the specified ports on a target IP
// Returns open ports with service names from common-ports.json
// portFoundChan receives each port as it's discovered (optional, for live updates)
func ScanPorts(ctx context.Context, ip string, ports []int, config ScanConfig, progressChan chan<- ScanProgress, portFoundChan chan<- PortResult) ([]PortResult, error) {
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports to scan")
	}

	results := make([]PortResult, 0, 64) // Pre-allocate for typical case
	var resultsMu sync.Mutex
	var scanned int64
	total := len(ports)

	// Create service lookup map
	serviceMap := make(map[int]string)
	for _, cp := range GetCommonPorts() {
		serviceMap[cp.Port] = cp.Service
	}

	// Worker pool
	sem := make(chan struct{}, config.Concurrent)
	var wg sync.WaitGroup

	timeout := time.Duration(config.TimeoutMs) * time.Millisecond
	pauseDuration := time.Duration(config.PauseMs) * time.Millisecond

	for i, port := range ports {
		select {
		case <-ctx.Done():
			waitWithTimeout(&wg, 2*time.Second)
			return results, ctx.Err()
		default:
		}

		wg.Add(1)

		// Non-blocking semaphore acquire with context check
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			waitWithTimeout(&wg, 2*time.Second)
			return results, ctx.Err()
		}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			// Check context before scanning
			select {
			case <-ctx.Done():
				return
			default:
			}

			if isPortOpen(ip, p, timeout) {
				port := PortResult{Port: p, Service: serviceMap[p]}
				resultsMu.Lock()
				results = append(results, port)
				foundCount := len(results)
				resultsMu.Unlock()

				// Send to live update channel
				if portFoundChan != nil {
					select {
					case portFoundChan <- port:
					default:
					}
				}

				// Send progress with new port
				scannedNow := atomic.AddInt64(&scanned, 1)
				if progressChan != nil {
					select {
					case progressChan <- ScanProgress{
						Total: total, Scanned: int(scannedNow),
						Found: foundCount, Completed: false,
					}:
					default:
					}
				}
			} else {
				scannedNow := atomic.AddInt64(&scanned, 1)
				if progressChan != nil {
					select {
					case progressChan <- ScanProgress{
						Total: total, Scanned: int(scannedNow),
						Found: -1, Completed: false, // -1 signals no change in found count
					}:
					default:
					}
				}
			}
		}(port)

		if pauseDuration > 0 && (i+1)%config.Concurrent == 0 {
			time.Sleep(pauseDuration)
		}
	}

	wg.Wait()

	if progressChan != nil {
		progressChan <- ScanProgress{Total: total, Scanned: total, Found: len(results), Completed: true}
	}

	return results, nil
}

// ScanCommonPorts scans only the common application ports
func ScanCommonPorts(ctx context.Context, ip string, config ScanConfig, progressChan chan<- ScanProgress, portFoundChan chan<- PortResult) ([]PortResult, error) {
	cp := GetCommonPorts()
	ports := make([]int, len(cp))
	for i, p := range cp {
		ports[i] = p.Port
	}
	return ScanPorts(ctx, ip, ports, config, progressChan, portFoundChan)
}

// ScanRange scans a port range
func ScanRange(ctx context.Context, ip string, start, end int, config ScanConfig, progressChan chan<- ScanProgress, portFoundChan chan<- PortResult) ([]PortResult, error) {
	ports := make([]int, 0, end-start+1)
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}
	return ScanPorts(ctx, ip, ports, config, progressChan, portFoundChan)
}

// ScanFull scans all 65535 ports
func ScanFull(ctx context.Context, ip string, config ScanConfig, progressChan chan<- ScanProgress, portFoundChan chan<- PortResult) ([]PortResult, error) {
	return ScanRange(ctx, ip, 1, 65535, config, progressChan, portFoundChan)
}

func isPortOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
