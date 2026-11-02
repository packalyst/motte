package vpn

import (
	"context"
	"testing"
)

// A scan stopped and replaced by a newer one doesn't free the newer one's slot when it ends: the
// newer scan stays stoppable, and a third can't start beside it.
func TestScanSlotSurvivesOldScanEnding(t *testing.T) {
	const id = "client-scan-test"
	t.Cleanup(func() { stopScan(id) })

	ctxA, cancelA := context.WithCancel(context.Background())
	a := reserveScan(id, cancelA)
	if a == nil {
		t.Fatal("first scan refused")
	}
	if reserveScan(id, func() {}) != nil {
		t.Fatal("a second scan started beside the first")
	}
	if !stopScan(id) || ctxA.Err() == nil {
		t.Fatal("stop didn't cancel the running scan")
	}
	ctxB, cancelB := context.WithCancel(context.Background())
	b := reserveScan(id, cancelB)
	if b == nil {
		t.Fatal("a new scan couldn't start after stop")
	}
	releaseScan(id, a) // scan A's goroutine ends after B started
	if reserveScan(id, func() {}) != nil {
		t.Fatal("old scan ending freed the new scan's slot: a third started")
	}
	if !stopScan(id) || ctxB.Err() == nil {
		t.Fatal("the new scan can't be stopped")
	}
	releaseScan(id, b)
	if c := reserveScan(id, func() {}); c == nil {
		t.Fatal("slot not free after the new scan ended")
	}
}
