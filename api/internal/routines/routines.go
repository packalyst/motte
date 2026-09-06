// Package routines is a lightweight supervisor for the panel's background jobs.
// Each periodic job registers a Spec; the supervisor owns the timer loop and
// records last/next-run + result + a short history, and exposes pause / resume /
// run-now — so these jobs are visible and controllable (the Routines page)
// instead of invisible fire-and-forget goroutines that need an api restart to
// change. Long-running daemons (WS hub, watchers) register read-only via
// RegisterDaemon so they show up as status rows without controls.
//
// This is a LEAF package (standard library only) so any package — even
// low-level ones like helper — can register without an import cycle. The HTTP
// layer lives in a separate package (routinesapi) that imports this and router.
package routines

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// manualRunCooldown throttles back-to-back run-now requests per routine so an
// authenticated caller can't drive a heavy job (e.g. geo-update) in a tight loop.
const manualRunCooldown = 3 * time.Second

// Status is a routine's current lifecycle state.
type Status string

const (
	StatusIdle    Status = "idle"    // registered, waiting for the next tick
	StatusRunning Status = "running" // executing now
	StatusPaused  Status = "paused"  // scheduled runs skipped until resumed
	StatusError   Status = "error"   // last run returned an error
)

// Kind distinguishes a supervised periodic job from a read-only daemon row.
type Kind string

const (
	KindInterval Kind = "interval" // runs every Interval
	KindDaily    Kind = "daily"    // runs on a time-of-day / custom schedule
	KindDaemon   Kind = "daemon"   // a continuous loop the supervisor only reflects (read-only)
)

const historyMax = 10 // last-N runs kept per routine

// Spec describes a periodic routine passed to Register. Exactly one schedule is
// used, in precedence order: NextRun, then DailyAt, then Interval.
type Spec struct {
	Name        string // unique, kebab-case id (also the API path segment + WS identity)
	Description string // one line: what it does
	Interval    time.Duration
	DailyAt     string                        // "HH:MM" local time
	NextRun     func(now time.Time) time.Time // full control: returns the next fire time
	Schedule    string                        // human label for NextRun (e.g. "daily at configured hour")
	RunAtStart  bool                          // also run once immediately when the loop starts
	Run         func(ctx context.Context) error
}

// RunRecord is one entry in a routine's run history.
type RunRecord struct {
	At         int64   `json:"at"`          // unix seconds (start)
	DurationMs float64 `json:"duration_ms"` // milliseconds
	Error      string  `json:"error,omitempty"`
}

// Info is an immutable snapshot of a routine's state for the API/UI.
type Info struct {
	Name         string      `json:"name"`
	Description  string      `json:"description"`
	Kind         Kind        `json:"kind"`
	Schedule     string      `json:"schedule"` // human: "every 1h0m0s", "daily at 03:00", "continuous"
	Status       Status      `json:"status"`
	Paused       bool        `json:"paused"`
	LastRun      *int64      `json:"last_run,omitempty"`
	LastDuration float64     `json:"last_duration_ms,omitempty"`
	LastError    string      `json:"last_error,omitempty"`
	NextRun      *int64      `json:"next_run,omitempty"`
	Runs         int64       `json:"runs"`
	History      []RunRecord `json:"history,omitempty"`
}

type routine struct {
	spec     Spec
	kind     Kind
	schedule string
	next     func(now time.Time) time.Time // nil for daemons

	mu         sync.Mutex
	status     Status
	paused     bool
	lastRun    time.Time
	lastManual time.Time // last accepted run-now (for the cooldown)
	lastDur    time.Duration
	lastErr    error
	nextRun    time.Time
	runs       int64
	history    []RunRecord

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
	if started {
		return // idempotent: never spawn a second loop per routine
	}
	rootCtx = ctx
	started = true
	for _, r := range reg {
		if r.kind != KindDaemon {
			go r.loop(ctx)
		}
	}
}

// Register adds a periodic routine. A duplicate name is ignored (first wins).
// An invalid spec (no name/run, or no valid schedule) is dropped.
func Register(spec Spec) {
	if spec.Name == "" || spec.Run == nil {
		return
	}
	r := &routine{spec: spec, status: StatusIdle, trigger: make(chan struct{}, 1)}
	switch {
	case spec.NextRun != nil:
		r.kind = KindDaily
		r.next = spec.NextRun
		r.schedule = spec.Schedule
		if r.schedule == "" {
			r.schedule = "scheduled"
		}
	case spec.DailyAt != "":
		hh, mm, ok := parseHHMM(spec.DailyAt)
		if !ok {
			return
		}
		r.kind = KindDaily
		r.next = func(now time.Time) time.Time { return nextDaily(now, hh, mm) }
		r.schedule = "daily at " + spec.DailyAt
	case spec.Interval > 0:
		iv := spec.Interval
		r.kind = KindInterval
		r.next = func(now time.Time) time.Time { return now.Add(iv) }
		r.schedule = "every " + humanDuration(iv)
	default:
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if _, ok := reg[spec.Name]; ok {
		return
	}
	reg[spec.Name] = r
	if started && rootCtx != nil {
		go r.loop(rootCtx)
	}
}

// RegisterDaemon adds a read-only status row for a continuous background loop
// (WS hub, watchers…) that the supervisor does NOT own — it just reflects that
// the loop is running. No schedule, no controls.
func RegisterDaemon(name, description string) {
	if name == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := reg[name]; ok {
		return
	}
	reg[name] = &routine{
		spec:     Spec{Name: name, Description: description},
		kind:     KindDaemon,
		schedule: "continuous",
		status:   StatusRunning,
	}
}

func (r *routine) loop(ctx context.Context) {
	if r.spec.RunAtStart {
		r.execute(ctx)
	}
	timer := time.NewTimer(r.computeNext())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if !r.isPaused() {
				r.execute(ctx)
			}
			timer.Reset(r.computeNext())
		case <-r.trigger:
			r.execute(ctx) // run-now overrides pause
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(r.computeNext())
		}
	}
}

// computeNext records the next scheduled time and returns the delay until then.
func (r *routine) computeNext() time.Duration {
	now := time.Now()
	nt := r.next(now)
	if !nt.After(now) {
		nt = now.Add(time.Second)
	}
	r.mu.Lock()
	r.nextRun = nt
	r.mu.Unlock()
	return time.Until(nt)
}

// execute runs the job once, recording timing/result/history. Only ever called
// from the single loop goroutine, so runs never overlap for a routine.
func (r *routine) execute(ctx context.Context) {
	r.mu.Lock()
	r.status = StatusRunning
	r.mu.Unlock()
	notify()

	start := time.Now()
	err := safeRun(ctx, r.spec.Run)
	dur := time.Since(start)

	r.mu.Lock()
	r.lastRun = start
	r.lastDur = dur
	r.lastErr = err
	r.runs++
	rec := RunRecord{At: start.Unix(), DurationMs: msOf(dur)}
	if err != nil {
		rec.Error = err.Error()
		r.status = StatusError
	} else if r.paused {
		r.status = StatusPaused
	} else {
		r.status = StatusIdle
	}
	r.history = append(r.history, rec)
	if len(r.history) > historyMax {
		r.history = r.history[len(r.history)-historyMax:]
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
		Kind:        r.kind,
		Schedule:    r.schedule,
		Status:      r.status,
		Paused:      r.paused,
		Runs:        r.runs,
	}
	if !r.lastRun.IsZero() {
		ts := r.lastRun.Unix()
		i.LastRun = &ts
		i.LastDuration = msOf(r.lastDur)
	}
	if r.lastErr != nil {
		i.LastError = r.lastErr.Error()
	}
	if r.kind != KindDaemon && !r.nextRun.IsZero() && !r.paused {
		ts := r.nextRun.Unix()
		i.NextRun = &ts
	}
	if len(r.history) > 0 {
		i.History = append([]RunRecord(nil), r.history...)
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

// controllable reports whether a routine accepts run/pause/resume (daemons don't).
func (r *routine) controllable() bool { return r != nil && r.kind != KindDaemon }

// RunNow triggers an immediate run (non-blocking). Returns false for an unknown
// name or a daemon. A run already queued is coalesced.
func RunNow(name string) bool {
	r := get(name)
	if !r.controllable() {
		return false
	}
	r.mu.Lock()
	if time.Since(r.lastManual) < manualRunCooldown {
		r.mu.Unlock()
		return true // throttled: recently run by hand, coalesce
	}
	r.lastManual = time.Now()
	r.mu.Unlock()
	select {
	case r.trigger <- struct{}{}:
	default:
	}
	return true
}

// Pause skips future scheduled runs until Resume (run-now still works).
func Pause(name string) bool {
	r := get(name)
	if !r.controllable() {
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

// Resume re-enables scheduled runs.
func Resume(name string) bool {
	r := get(name)
	if !r.controllable() {
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
// Stored atomically so setting it can't race with the routine goroutines reading it.
var broadcaster atomic.Pointer[func([]Info)]

// SetBroadcaster registers the live-update callback. Called outside all locks, so
// it is safe to call List()/anything from within it.
func SetBroadcaster(fn func([]Info)) { broadcaster.Store(&fn) }

func notify() {
	if p := broadcaster.Load(); p != nil {
		(*p)(List())
	}
}

// --- helpers ---------------------------------------------------------------

func msOf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

// parseHHMM parses "HH:MM" (24h). Returns ok=false on any malformed input.
func parseHHMM(s string) (hh, mm int, ok bool) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, 0, false
	}
	return t.Hour(), t.Minute(), true
}

// nextDaily returns the next occurrence of hh:mm local time strictly after now.
func nextDaily(now time.Time, hh, mm int) time.Time {
	n := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, now.Location())
	if !n.After(now) {
		n = n.Add(24 * time.Hour)
	}
	return n
}

// humanDuration renders a schedule interval compactly (e.g. "24h", "5m", "30s").
func humanDuration(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return fmt.Sprintf("%ds", d/time.Second)
	}
}
