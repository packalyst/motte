package fleet

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func bulkReq(t *testing.T, body string) *http.Request {
	t.Helper()
	return asOwner(httptest.NewRequest(http.MethodPost, "/api/fleet/bulk-command", bytes.NewReader([]byte(body))))
}

func TestBulkCommand(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", 0)
	addMachine(t, svc, "m2", 0)

	// Allow-tier command across two machines: no step-up, both queued.
	rr := httptest.NewRecorder()
	svc.handleBulkCommand(rr, bulkReq(t, `{"machine_ids":["m1","m2"],"type":"block","payload":{"ip":"203.0.113.7"}}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("allow-tier bulk: status %d, body %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Queued  int `json:"queued"`
		Total   int `json:"total"`
		Results []struct {
			OK bool `json:"ok"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Queued != 2 || resp.Total != 2 {
		t.Fatalf("expected 2 queued/2 total, got queued=%d total=%d", resp.Queued, resp.Total)
	}

	// Confirm-tier command with no step-up credential: whole batch is refused with 428 before
	// anything is queued (step-up verified once).
	rr2 := httptest.NewRecorder()
	svc.handleBulkCommand(rr2, bulkReq(t, `{"machine_ids":["m1","m2"],"type":"restart"}`))
	if rr2.Code != http.StatusPreconditionRequired {
		t.Fatalf("confirm-tier bulk without auth: status %d, want 428", rr2.Code)
	}

	// Empty machine list is a 400.
	rr3 := httptest.NewRecorder()
	svc.handleBulkCommand(rr3, bulkReq(t, `{"machine_ids":[],"type":"block"}`))
	if rr3.Code != http.StatusBadRequest {
		t.Fatalf("empty machine_ids: status %d, want 400", rr3.Code)
	}
}
