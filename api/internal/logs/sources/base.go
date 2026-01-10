package sources

import (
	"context"

	"api/internal/logs"
)

// BaseWatcher provides common watcher functionality
type BaseWatcher struct {
	name   string
	tailer *logs.FileTailer
	cancel context.CancelFunc
}

// NewBaseWatcher creates a new base watcher
func NewBaseWatcher(name string, tailer *logs.FileTailer) BaseWatcher {
	return BaseWatcher{
		name:   name,
		tailer: tailer,
	}
}

// Name returns the watcher name
func (b *BaseWatcher) Name() string {
	return b.name
}

// Start starts the watcher with the given line processor
func (b *BaseWatcher) Start(ctx context.Context, processLine func(string)) error {
	ctx, b.cancel = context.WithCancel(ctx)
	return b.tailer.Tail(ctx, processLine)
}

// Stop stops the watcher
func (b *BaseWatcher) Stop() {
	if b.cancel != nil {
		b.cancel()
	}
}

// IsRunning returns whether the watcher is running
func (b *BaseWatcher) IsRunning() bool {
	return b.tailer.IsRunning()
}

// Processed returns the number of lines processed
func (b *BaseWatcher) Processed() int64 {
	return b.tailer.Processed()
}

// LastError returns the last error
func (b *BaseWatcher) LastError() string {
	return b.tailer.LastError()
}

// Tailer returns the underlying file tailer
func (b *BaseWatcher) Tailer() *logs.FileTailer {
	return b.tailer
}
