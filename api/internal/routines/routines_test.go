package routines

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// reset clears global state between tests (the registry is a package singleton).
func reset() {
	mu.Lock()
	reg = map[string]*routine{}
	rootCtx = nil
	started = false
	mu.Unlock()
	broadcaster.Store(nil)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

func TestRunAtStartAndList(t *testing.T) {
	reset()
	var runs int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Init(ctx)

	Register(Spec{
		Name: "job", Description: "test", Interval: time.Hour, RunAtStart: true,
		Run: func(context.Context) error { atomic.AddInt32(&runs, 1); return nil },
	})

	waitFor(t, func() bool { return atomic.LoadInt32(&runs) == 1 })

	l := List()
	if len(l) != 1 || l[0].Name != "job" {
		t.Fatalf("expected one routine 'job', got %+v", l)
	}
	if l[0].Runs != 1 || l[0].Status != StatusIdle || l[0].LastRun == nil || l[0].NextRun == nil {
		t.Errorf("unexpected info after one run: %+v", l[0])
	}
}

func TestRunNow(t *testing.T) {
	reset()
	var runs int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Init(ctx)
	Register(Spec{
		Name: "j", Interval: time.Hour,
		Run: func(context.Context) error { atomic.AddInt32(&runs, 1); return nil },
	})
	if !RunNow("j") {
		t.Fatal("RunNow returned false for a known routine")
	}
	waitFor(t, func() bool { return atomic.LoadInt32(&runs) == 1 })
	if RunNow("nope") {
		t.Error("RunNow should return false for an unknown routine")
	}
}

func TestPauseSkipsScheduledButRunNowOverrides(t *testing.T) {
	reset()
	var runs int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Init(ctx)
	Register(Spec{
		Name: "p", Interval: 20 * time.Millisecond,
		Run: func(context.Context) error { atomic.AddInt32(&runs, 1); return nil },
	})
	Pause("p")
	time.Sleep(120 * time.Millisecond) // several intervals would have elapsed
	if n := atomic.LoadInt32(&runs); n != 0 {
		t.Fatalf("paused routine should not run on schedule, ran %d times", n)
	}
	RunNow("p") // manual override works while paused
	waitFor(t, func() bool { return atomic.LoadInt32(&runs) == 1 })
	Resume("p")
	waitFor(t, func() bool { return atomic.LoadInt32(&runs) >= 2 })
}

func TestErrorAndPanicAreRecorded(t *testing.T) {
	reset()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Init(ctx)
	Register(Spec{
		Name: "e", Interval: time.Hour, RunAtStart: true,
		Run: func(context.Context) error { return errors.New("boom") },
	})
	Register(Spec{
		Name: "panicky", Interval: time.Hour, RunAtStart: true,
		Run: func(context.Context) error { panic("kaboom") },
	})
	waitFor(t, func() bool {
		for _, i := range List() {
			if i.Name == "e" && i.LastError != "boom" {
				return false
			}
			if i.Name == "panicky" && i.LastError == "" {
				return false
			}
		}
		return true
	})
	for _, i := range List() {
		if i.Status != StatusError {
			t.Errorf("%s should be in error status, got %s", i.Name, i.Status)
		}
	}
}

func TestDuplicateRegisterIgnored(t *testing.T) {
	reset()
	Register(Spec{Name: "dup", Interval: time.Hour, Run: func(context.Context) error { return nil }})
	Register(Spec{Name: "dup", Interval: time.Hour, Run: func(context.Context) error { return nil }})
	if len(List()) != 1 {
		t.Fatalf("duplicate name should be ignored, got %d routines", len(List()))
	}
}

func TestHistoryRingBuffer(t *testing.T) {
	reset()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Init(ctx)
	Register(Spec{Name: "h", Interval: 5 * time.Millisecond, Run: func(context.Context) error { return nil }})
	waitFor(t, func() bool {
		for _, i := range List() {
			if i.Name == "h" && i.Runs > historyMax+2 {
				return true
			}
		}
		return false
	})
	for _, i := range List() {
		if i.Name == "h" && len(i.History) > historyMax {
			t.Fatalf("history should be capped at %d, got %d", historyMax, len(i.History))
		}
	}
}

func TestDaemonIsReadOnly(t *testing.T) {
	reset()
	RegisterDaemon("ws-hub", "WebSocket hub")
	l := List()
	if len(l) != 1 || l[0].Kind != KindDaemon || l[0].Status != StatusRunning || l[0].Schedule != "continuous" {
		t.Fatalf("unexpected daemon info: %+v", l)
	}
	if l[0].NextRun != nil {
		t.Error("daemon must not have a next run")
	}
	if RunNow("ws-hub") || Pause("ws-hub") || Resume("ws-hub") {
		t.Error("daemon must not be controllable")
	}
}

func TestDailySchedule(t *testing.T) {
	reset()
	// nextDaily always returns a time strictly after now, at the right clock time.
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.Local)
	got := nextDaily(now, 3, 30) // 03:30 already passed today → tomorrow
	if got.Hour() != 3 || got.Minute() != 30 || !got.After(now) || got.Day() != 2 {
		t.Errorf("nextDaily wrong: %v", got)
	}
	later := nextDaily(now, 15, 0) // 15:00 still ahead today
	if later.Day() != 1 || later.Hour() != 15 {
		t.Errorf("nextDaily should be today 15:00: %v", later)
	}
	if hh, mm, ok := parseHHMM("03:07"); !ok || hh != 3 || mm != 7 {
		t.Errorf("parseHHMM 03:07 → %d %d %v", hh, mm, ok)
	}
	if _, _, ok := parseHHMM("nope"); ok {
		t.Error("parseHHMM should reject bad input")
	}
	// Register with DailyAt reports a daily schedule label + next run.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Init(ctx)
	Register(Spec{Name: "d", DailyAt: "03:00", Run: func(context.Context) error { return nil }})
	l := List()
	if len(l) != 1 || l[0].Kind != KindDaily || l[0].Schedule != "daily at 03:00" {
		t.Fatalf("unexpected daily routine: %+v", l)
	}
}
