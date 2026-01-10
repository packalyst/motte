package nftables

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"

	"api/internal/database"
)

const (
	defaultDebounceDelay = 500 * time.Millisecond
)

var (
	instance   *Service
	instanceMu sync.RWMutex
)

// New creates a new nftables service
func New() (*Service, error) {
	db, err := database.GetDB()
	if err != nil {
		return nil, err
	}

	svc := &Service{
		db:            db,
		tables:        make(map[string]Table),
		debounceDelay: defaultDebounceDelay,
	}

	instanceMu.Lock()
	instance = svc
	instanceMu.Unlock()

	log.Printf("nftables service initialized")
	return svc, nil
}

// GetService returns the global service instance
func GetService() *Service {
	instanceMu.RLock()
	defer instanceMu.RUnlock()
	return instance
}

// SetBroadcastFunc sets the WebSocket broadcast callback
func (s *Service) SetBroadcastFunc(fn func(channel string, data interface{})) {
	s.broadcastFn = fn
}

// RegisterTable registers a table builder
func (s *Service) RegisterTable(t Table) {
	s.applyMutex.Lock()
	defer s.applyMutex.Unlock()
	s.tables[t.Name()] = t
	log.Printf("nftables: registered table %s %s", t.Family(), t.Name())
}

// broadcast sends a WebSocket event via general_info channel
func (s *Service) broadcast(event, status, message string, data interface{}) {
	if s.broadcastFn == nil {
		return
	}
	s.broadcastFn("general_info", map[string]interface{}{
		"event":   event,
		"status":  status,
		"message": message,
		"data":    data,
	})
}

// RequestApply schedules a debounced apply
func (s *Service) RequestApply() {
	s.applyMutex.Lock()
	defer s.applyMutex.Unlock()

	if s.applyTimer != nil {
		s.applyTimer.Stop()
	}

	s.applyPending = true
	s.broadcast("firewall:pending", "pending", "Changes queued", nil)

	s.applyTimer = time.AfterFunc(s.debounceDelay, func() {
		s.broadcast("firewall:applying", "applying", "Applying rules...", nil)

		err := s.ApplyAll()

		s.applyMutex.Lock()
		s.applyPending = false
		s.applyTimer = nil
		s.lastApplyErr = err
		if err == nil {
			s.lastApplyAt = time.Now()
		}
		s.applyMutex.Unlock()

		if err != nil {
			log.Printf("nftables: apply failed: %v", err)
			s.broadcast("firewall:error", "error", "Apply failed", map[string]string{"error": err.Error()})
		} else {
			stats := s.GetStats()
			log.Printf("nftables: applied successfully")
			s.broadcast("firewall:applied", "applied", "Rules applied", stats)
		}
	})
}

// ApplyAll applies all registered tables
func (s *Service) ApplyAll() error {
	s.applyMutex.Lock()
	tables := make([]Table, 0, len(s.tables))
	for _, t := range s.tables {
		tables = append(tables, t)
	}
	s.applyMutex.Unlock()

	// Sort by priority
	sort.Slice(tables, func(i, j int) bool {
		return tables[i].Priority() < tables[j].Priority()
	})

	for _, t := range tables {
		if err := s.applyTable(t); err != nil {
			return fmt.Errorf("table %s: %w", t.Name(), err)
		}
	}

	return nil
}

func (s *Service) applyTable(t Table) error {
	script, err := t.Build()
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}

	// Prepend delete command to script for atomic replacement
	// (nft flush table only clears chains, NOT set elements!)
	// Using "delete table" before the new table definition ensures clean state
	deletePrefix := fmt.Sprintf("delete table %s %s\n", t.Family(), t.Name())
	atomicScript := deletePrefix + script

	if err := s.ApplyScript(atomicScript); err != nil {
		// If delete fails (table doesn't exist), try without delete
		if err := s.ApplyScript(script); err != nil {
			return fmt.Errorf("apply: %w", err)
		}
	}

	return nil
}

// Exec runs an nft command
func (s *Service) Exec(args ...string) ([]byte, error) {
	cmd := exec.Command("nft", args...)
	return cmd.CombinedOutput()
}

// ApplyScript writes and applies an nft script
func (s *Service) ApplyScript(script string) error {
	tmpFile := fmt.Sprintf("/tmp/nftables-%d.nft", time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, []byte(script), 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	defer os.Remove(tmpFile)

	out, err := s.Exec("-f", tmpFile)
	if err != nil {
		return fmt.Errorf("nft: %v - %s", err, string(out))
	}

	return nil
}

// TableExists checks if a table exists
func (s *Service) TableExists(family, name string) bool {
	out, err := s.Exec("list", "table", family, name)
	return err == nil && len(out) > 0
}

// CountSetElements counts elements in a named set
func (s *Service) CountSetElements(family, table, setName string) int {
	out, err := s.Exec("list", "set", family, table, setName)
	if err != nil {
		return 0
	}
	return ParseSetElementCount(string(out), setName)
}

// GetFirewallSetCounts returns element counts for all firewall sets
func (s *Service) GetFirewallSetCounts() map[string]int {
	return map[string]int{
		"blocked_ips":           s.CountSetElements("inet", "wgadmin_firewall", "blocked_ips"),
		"blocked_ranges":        s.CountSetElements("inet", "wgadmin_firewall", "blocked_ranges"),
		"blocked_countries":     s.CountSetElements("inet", "wgadmin_firewall", "blocked_countries"),
		"blocked_ips_out":       s.CountSetElements("inet", "wgadmin_firewall", "blocked_ips_out"),
		"blocked_ranges_out":    s.CountSetElements("inet", "wgadmin_firewall", "blocked_ranges_out"),
		"blocked_countries_out": s.CountSetElements("inet", "wgadmin_firewall", "blocked_countries_out"),
		"allowed_tcp_ports":     s.CountSetElements("inet", "wgadmin_firewall", "allowed_tcp_ports"),
		"allowed_udp_ports":     s.CountSetElements("inet", "wgadmin_firewall", "allowed_udp_ports"),
	}
}

// GetStats returns statistics about applied rules
func (s *Service) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	for name, t := range s.tables {
		tableStats := map[string]interface{}{
			"exists": s.TableExists(t.Family(), t.Name()),
		}
		stats[name] = tableStats
	}

	return stats
}

// GetSyncStatus returns the current sync status
func (s *Service) GetSyncStatus() SyncStatus {
	s.applyMutex.Lock()
	status := SyncStatus{
		ApplyPending: s.applyPending,
		LastApplyAt:  s.lastApplyAt,
	}
	if s.lastApplyErr != nil {
		status.LastApplyError = s.lastApplyErr.Error()
	}
	s.applyMutex.Unlock()

	status.InSync = true
	for name, t := range s.tables {
		ts := TableStatus{
			Name:   name,
			Family: t.Family(),
			Exists: s.TableExists(t.Family(), t.Name()),
		}
		if !ts.Exists {
			status.InSync = false
		}
		status.Tables = append(status.Tables, ts)
	}

	if status.ApplyPending || status.LastApplyError != "" {
		status.InSync = false
	}

	return status
}

// Stop cancels pending applies
func (s *Service) Stop() {
	s.applyMutex.Lock()
	defer s.applyMutex.Unlock()

	if s.applyTimer != nil {
		s.applyTimer.Stop()
		s.applyTimer = nil
	}
}
