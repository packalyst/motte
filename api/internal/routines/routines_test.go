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
