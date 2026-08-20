package serverstats

import "testing"

func TestCPUBusy(t *testing.T) {
	cases := []struct {
		name      string
		prev, cur cpuSample
		want      float64
	}{
		// 1000 jiffies elapsed, 800 of them idle → 20% busy.
		{"quarter-ish", cpuSample{total: 1000, idle: 800}, cpuSample{total: 2000, idle: 1600}, 20},
		// fully idle
		{"idle", cpuSample{total: 100, idle: 100}, cpuSample{total: 200, idle: 200}, 0},
		// fully busy
		{"pegged", cpuSample{total: 100, idle: 50}, cpuSample{total: 200, idle: 50}, 100},
		// no elapsed jiffies → guard returns 0, not NaN
		{"no-delta", cpuSample{total: 500, idle: 400}, cpuSample{total: 500, idle: 400}, 0},
	}
	for _, c := range cases {
		if got := cpuBusy(c.prev, c.cur); got != c.want {
			t.Errorf("%s: cpuBusy=%v want %v", c.name, got, c.want)
		}
	}
}

func TestClampRound(t *testing.T) {
	if clamp(-5) != 0 || clamp(150) != 100 || clamp(42) != 42 {
		t.Fatal("clamp out of spec")
	}
	if round1(19.96) != 20.0 || round1(33.34) != 33.3 {
		t.Fatalf("round1 out of spec: %v %v", round1(19.96), round1(33.34))
	}
}

// The first sample after a cold start (or an idle gap) has no baseline to diff
// against, so it must report ok=false; the next one, with a fresh baseline,
// reports ok=true. Reads real /proc, so it runs on Linux CI only.
func TestSampleBaseline(t *testing.T) {
	c := New(nil, nil)
	if _, ok := c.sample(); ok {
		t.Fatal("first sample should have no baseline (ok=false)")
	}
	if _, ok := c.sample(); !ok {
		t.Fatal("second sample should compute against the baseline (ok=true)")
	}
}
