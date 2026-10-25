package backup

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"api/internal/events"
	"api/internal/routines"
)

// RunStatus is a lightweight, in-memory view of the most recent scheduled/manual run for the UI.
type RunStatus struct {
	Running   bool       `json:"running"`
	LastTime  *time.Time `json:"lastTime,omitempty"` // nil until a run has happened (a zero time.Time isn't omitted)
	LastOK    bool       `json:"lastOK"`
	LastError string     `json:"lastError,omitempty"`
	LastSize  int64      `json:"lastSize,omitempty"`
}

var (
	offhostMu sync.Mutex
	offhost   RunStatus
)

// Status returns a copy of the latest off-host run status.
func (s *Service) Status() RunStatus {
	offhostMu.Lock()
	defer offhostMu.Unlock()
	return offhost
}

// runOffhost builds one sealed backup (Export) and uploads it to every configured destination,
// pinning a first-seen SFTP host key and pruning old archives. actor is the audit attribution
// ("scheduler" for the timer). Only one run proceeds at a time.
func (s *Service) runOffhost(ctx context.Context, actor string) error {
	offhostMu.Lock()
	if offhost.Running {
		offhostMu.Unlock()
		return fmt.Errorf("a backup is already running")
	}
	offhost.Running = true
	offhostMu.Unlock()

	var runErr error
	var size int64
	defer func() {
		offhostMu.Lock()
		offhost.Running = false
		now := time.Now()
		offhost.LastTime = &now
		offhost.LastOK = runErr == nil
		offhost.LastSize = size
		offhost.LastError = ""
		if runErr != nil {
			offhost.LastError = runErr.Error()
		}
		offhostMu.Unlock()
		if runErr != nil {
			events.Audit("backup", "offhost_failed", events.SeverityWarning, actor, "",
				fmt.Sprintf("Off-host backup failed: %v", runErr))
		}
	}()

	cfg, err := s.loadOffhostConfig()
	if err != nil {
		runErr = fmt.Errorf("load config: %w", err)
		return runErr
	}
	if err := cfg.validate(); err != nil {
		runErr = err
		return runErr
	}
	db := s.db()
	if db == nil {
		runErr = fmt.Errorf("database unavailable")
		return runErr
	}

	// The sealed bundle is the same artifact a user can download by hand.
	data, err := Export(db, cfg.Passphrase, s.deps.PanelVersion, cfg.IncludeUsers, cfg.IncludeFleet)
	if err != nil {
		runErr = fmt.Errorf("export: %w", err)
		return runErr
	}
	size = int64(len(data))

	tmp, err := os.CreateTemp("", "motte-offhost-")
	if err != nil {
		runErr = err
		return runErr
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		runErr = err
		return runErr
	}
	tmp.Close()

	name := fmt.Sprintf("motte-%s.wgbackup", time.Now().Format("20060102-150405"))

	var pinned bool
	var okDests []string
	for i := range cfg.Destinations {
		d := cfg.Destinations[i]
		be, err := newBackend(d)
		if err != nil {
			runErr = fmt.Errorf("destination %q: %w", d.Name, err)
			return runErr
		}
		if err := be.put(ctx, tmpPath, name); err != nil {
			be.close()
			runErr = fmt.Errorf("upload to %q: %w", d.Name, err)
			return runErr
		}
		if d.HostKey == "" {
			if hk := be.learnedHostKey(); hk != "" {
				cfg.Destinations[i].HostKey = hk
				pinned = true
			}
		}
		if err := pruneKeepN(ctx, be, cfg.KeepN); err != nil {
			log.Printf("backup: prune on %q failed: %v", d.Name, err)
		}
		be.close()
		okDests = append(okDests, d.Name)
	}

	if pinned {
		if err := s.saveOffhostConfig(cfg); err != nil {
			log.Printf("backup: failed to persist pinned host key: %v", err)
		}
	}

	events.Audit("backup", "offhost_ok", events.SeverityInfo, actor, "",
		fmt.Sprintf("Off-host backup %s (%d bytes) uploaded to %d destination(s): %v", name, size, len(okDests), okDests))
	return nil
}

// restoreFromOffhost downloads a chosen archive, decrypts + applies it with the existing
// Open/Import, then reconciles live state. It overwrites panel state, so callers must step-up.
func (s *Service) restoreFromOffhost(ctx context.Context, destID, name, passphrase string) ([]string, error) {
	if !isArchiveName(name) {
		return nil, fmt.Errorf("invalid archive name")
	}
	cfg, err := s.loadOffhostConfig()
	if err != nil {
		return nil, err
	}
	d, ok := findDest(cfg, destID)
	if !ok {
		return nil, fmt.Errorf("destination not found")
	}
	if passphrase == "" {
		passphrase = cfg.Passphrase // default to the stored one
	}
	be, err := newBackend(d)
	if err != nil {
		return nil, err
	}
	defer be.close()

	tmp, err := os.CreateTemp("", "motte-restore-")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	if err := be.get(ctx, name, tmpPath); err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	raw, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, err
	}
	_, doc, err := Open(raw, passphrase)
	if err != nil {
		return nil, err
	}
	db := s.db()
	if db == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	if err := Import(db, doc); err != nil {
		return nil, fmt.Errorf("import failed: %w", err)
	}
	var reconciled []string
	if s.deps.Reconcile != nil {
		reconciled = s.deps.Reconcile()
	}
	return reconciled, nil
}

// Start launches the scheduler: a ticker that fires the daily backup at the configured hour when
// enabled. It never runs at boot and re-reads config each tick so changes apply without a restart.
func (s *Service) Start() {
	routines.RegisterDaemon("backup-scheduler", "Off-host backup: runs the daily sealed backup at the configured hour")
	go func() {
		t := time.NewTicker(20 * time.Minute)
		defer t.Stop()
		var lastRunDay string
		for range t.C {
			cfg, err := s.loadOffhostConfig()
			if err != nil || !cfg.Enabled {
				continue
			}
			now := time.Now()
			day := now.Format("2006-01-02")
			if now.Hour() == cfg.Hour && day != lastRunDay {
				lastRunDay = day
				if err := s.runOffhost(context.Background(), "scheduler"); err != nil {
					log.Printf("backup: scheduled run failed: %v", err)
				}
			}
		}
	}()
}
