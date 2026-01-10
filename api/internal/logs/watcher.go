package logs

import (
	"bufio"
	"context"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Watcher interface for all log watchers
type Watcher interface {
	Name() string
	Start(ctx context.Context) error
	Stop()
	IsRunning() bool
	Processed() int64
	LastError() string
}

// FileTailer provides reusable file tailing functionality
type FileTailer struct {
	filePath    string
	lastSize    int64
	mu          sync.Mutex
	running     atomic.Bool
	processed   atomic.Int64
	lastError   atomic.Value
	pollInterval time.Duration
}

// NewFileTailer creates a new file tailer
func NewFileTailer(filePath string, pollInterval time.Duration) *FileTailer {
	ft := &FileTailer{
		filePath:     filePath,
		pollInterval: pollInterval,
	}
	ft.lastError.Store("")
	return ft
}

// Tail continuously tails a file and calls processLine for each new line
func (ft *FileTailer) Tail(ctx context.Context, processLine func(line string)) error {
	if _, err := os.Stat(ft.filePath); os.IsNotExist(err) {
		ft.lastError.Store("file not found: " + ft.filePath)
		return err
	}

	ft.running.Store(true)
	defer ft.running.Store(false)

	log.Printf("[%s] Starting file tailer", ft.filePath)

	ticker := time.NewTicker(ft.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[%s] File tailer stopping", ft.filePath)
			return nil
		case <-ticker.C:
			if err := ft.processNewLines(processLine); err != nil {
				ft.lastError.Store(err.Error())
			}
		}
	}
}

// processNewLines reads new lines since last position
func (ft *FileTailer) processNewLines(processLine func(line string)) error {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	file, err := os.Open(ft.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	currentSize := stat.Size()

	// File truncated or rotated - reset position
	if currentSize < ft.lastSize {
		ft.lastSize = 0
	}

	// No new data
	if currentSize == ft.lastSize {
		return nil
	}

	// First run - start from end to avoid processing old logs
	if ft.lastSize == 0 {
		ft.lastSize = currentSize
		return nil
	}

	// Seek to last position
	if _, err := file.Seek(ft.lastSize, 0); err != nil {
		return err
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			processLine(line)
			ft.processed.Add(1)
		}
	}

	ft.lastSize = currentSize
	ft.lastError.Store("")
	return scanner.Err()
}

// IsRunning returns whether the tailer is running
func (ft *FileTailer) IsRunning() bool {
	return ft.running.Load()
}

// Processed returns the number of lines processed
func (ft *FileTailer) Processed() int64 {
	return ft.processed.Load()
}

// LastError returns the last error message
func (ft *FileTailer) LastError() string {
	if v := ft.lastError.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Reset resets the file position (useful after rotation)
func (ft *FileTailer) Reset() {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.lastSize = 0
}
