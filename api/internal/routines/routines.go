// Package routines is a lightweight supervisor for the panel's periodic
// background jobs (Cloudflare-IP refresh, cleanups, samplers, …). Each job
// registers a Spec; the supervisor owns the timer loop and records last-run /
// next-run / result, and exposes pause / resume / run-now — so these jobs are
// visible and controllable (the Routines page) instead of invisible
// fire-and-forget goroutines that need an api restart to change.
//
// This is a LEAF package (standard library only) so any package — even
// low-level ones like helper — can register a routine without an import cycle.
// The HTTP layer lives in a separate package (routinesapi) that imports both
// this and router.
package routines

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Status is a routine's current lifecycle state.
type Status string

const (
	StatusIdle    Status = "idle"    // registered, waiting for the next tick
	StatusRunning Status = "running" // executing now
	StatusPaused  Status = "paused"  // scheduled ticks skipped until resumed
	StatusError   Status = "error"   // last run returned an error
)

// Spec describes a periodic routine passed to Register. Run must be safe to call
// repeatedly and should honor ctx for cancellation.
type Spec struct {
	Name        string // unique, kebab-case identifier
	Description string // one line: what it does
	Interval    time.Duration
	RunAtStart  bool // also run once immediately when the loop starts
	Run         func(ctx context.Context) error
}

// Info is an immutable snapshot of a routine's state for the API/UI.
type Info struct {
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	IntervalSec  int64   `json:"interval_sec"`
	Status       Status  `json:"status"`
	Paused       bool    `json:"paused"`
	LastRun      *int64  `json:"last_run,omitempty"`         // unix seconds
	LastDuration float64 `json:"last_duration_ms,omitempty"` // milliseconds
	LastError    string  `json:"last_error,omitempty"`
	NextRun      *int64  `json:"next_run,omitempty"` // unix seconds
	Runs         int64   `json:"runs"`
}

type routine struct {
	spec Spec

	mu      sync.Mutex
	status  Status
	paused  bool
	lastRun time.Time
	lastDur time.Duration
	lastErr error
	nextRun time.Time
	runs    int64

	trigger chan struct{} // run-now (buffered 1)
}

var (
	mu      sync.Mutex
	reg     = map[string]*routine{}
	rootCtx context.Context
	started bool
)

// Init sets the base context and starts any already-registered routines. Call
// once, early in main, before services register theirs.
func Init(ctx context.Context) {
	mu.Lock()
	defer mu.Unlock()
	rootCtx = ctx
	started = true
	for _, r := range reg {
		go r.loop(ctx)
	}
}

// Register adds a periodic routine. If the supervisor is already started the
// loop begins immediately, otherwise it starts on Init. A duplicate name is
// ignored (first wins) so a re-register can never spawn two loops. Invalid
// specs (no name/run or non-positive interval) are dropped.
func Register(spec Spec) {
	if spec.Name == "" || spec.Run == nil || spec.Interval <= 0 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := reg[spec.Name]; ok {
		return
	}
	r := &routine{spec: spec, status: StatusIdle, trigger: make(chan struct{}, 1)}
	reg[spec.Name] = r
	if started && rootCtx != nil {
		go r.loop(rootCtx)
	}
}

func (r *routine) loop(ctx context.Context) {
	if r.spec.RunAtStart {
		r.execute(ctx)
	}
	r.setNextRun(r.spec.Interval)
	timer := time.NewTimer(r.spec.Interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if !r.isPaused() {
				r.execute(ctx)
			}
			r.setNextRun(r.spec.Interval)
			timer.Reset(r.spec.Interval)
		case <-r.trigger:
			// Run-now overrides pause (an explicit manual action).
			r.execute(ctx)
			r.setNextRun(r.spec.Interval)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(r.spec.Interval)
		}
	}
}

// execute runs the job once, recording timing/result. Only ever called from the
// single loop goroutine, so runs never overlap for a routine.
func (r *routine) execute(ctx context.Context) {
	r.mu.Lock()
	r.status = StatusRunning
	r.mu.Unlock()
	notify()

	start := time.Now()
	err := safeRun(ctx, r.spec.Run)

	r.mu.Lock()
	r.lastRun = start
	r.lastDur = time.Since(start)
	r.lastErr = err
	r.runs++
	switch {
	case err != nil:
		r.status = StatusError
	case r.paused:
		r.status = StatusPaused
	default:
		r.status = StatusIdle
	}
	r.mu.Unlock()
	notify()
}

// safeRun recovers a panic in a job so one bad routine can't crash the process.
func safeRun(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return fn(ctx)
}

func (r *routine) setNextRun(d time.Duration) {
	r.mu.Lock()
	r.nextRun = time.Now().Add(d)
	r.mu.Unlock()
}

func (r *routine) isPaused() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.paused
}

func (r *routine) info() Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := Info{
		Name:        r.spec.Name,
		Description: r.spec.Description,
		IntervalSec: int64(r.spec.Interval / time.Second),
		Status:      r.status,
		Paused:      r.paused,
		Runs:        r.runs,
	}
	if !r.lastRun.IsZero() {
		ts := r.lastRun.Unix()
		i.LastRun = &ts
		i.LastDuration = float64(r.lastDur.Microseconds()) / 1000.0
	}
	if r.lastErr != nil {
		i.LastError = r.lastErr.Error()
	}
	if !r.nextRun.IsZero() && !r.paused {
		ts := r.nextRun.Unix()
		i.NextRun = &ts
	}
	return i
}

// List returns a snapshot of all routines, sorted by name.
func List() []Info {
	mu.Lock()
	rs := make([]*routine, 0, len(reg))
	for _, r := range reg {
		rs = append(rs, r)
	}
	mu.Unlock()
	out := make([]Info, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func get(name string) *routine {
	mu.Lock()
	defer mu.Unlock()
	return reg[name]
}

// RunNow triggers an immediate run (non-blocking). Returns false for an unknown
// name. A run already queued is coalesced (buffered channel of 1).
func RunNow(name string) bool {
	r := get(name)
	if r == nil {
		return false
	}
	select {
	case r.trigger <- struct{}{}:
	default:
	}
	return true
}

// Pause skips future scheduled runs until Resume (run-now still works). Returns
// false for an unknown name.
func Pause(name string) bool {
	r := get(name)
	if r == nil {
		return false
	}
	r.mu.Lock()
	r.paused = true
	if r.status != StatusRunning {
		r.status = StatusPaused
	}
	r.mu.Unlock()
	notify()
	return true
}

// Resume re-enables scheduled runs. Returns false for an unknown name.
func Resume(name string) bool {
	r := get(name)
	if r == nil {
		return false
	}
	r.mu.Lock()
	r.paused = false
	if r.status == StatusPaused {
		r.status = StatusIdle
	}
	r.mu.Unlock()
	notify()
	return true
}

// broadcaster, if set, is called with the full routine list whenever a routine's
// state changes, so the UI can update live over WebSocket instead of polling.
var broadcaster func([]Info)

// SetBroadcaster registers the live-update callback. Set once at startup. Called
// outside all locks, so it is safe to call List()/anything from within it.
func SetBroadcaster(fn func([]Info)) { broadcaster = fn }

func notify() {
	if broadcaster != nil {
		broadcaster(List())
	}
}
