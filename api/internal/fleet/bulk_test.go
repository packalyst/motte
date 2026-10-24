package fleet

import (
	"bytes"
	"encoding/json"
	"errors"
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
	addMachine(t, svc, "m1", true)
	addMachine(t, svc, "m2", true)

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

// A bulk blocklist push carries the panel's own list (never the request's), and a list the
// panel can't read stops the push instead of sending an empty one.
func TestBulkPushBlocksCarriesPanelList(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	svc.blockedIPs = func() ([]string, error) { return []string{"203.0.113.0/24", "198.51.100.9"}, nil }

	rr := httptest.NewRecorder()
	svc.handleBulkCommand(rr, bulkReq(t, `{"machine_ids":["m1"],"type":"sync-blocks","payload":{"ips":["192.0.2.1"]}}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rr.Code, rr.Body.String())
	}
	var payload string
	if err := svc.db.QueryRow(`SELECT payload FROM fleet_commands WHERE machine_id='m1' AND type='sync-blocks'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if payload != `{"ips":["203.0.113.0/24","198.51.100.9"]}` {
		t.Fatalf("pushed %s, want the panel's list", payload)
	}

	svc.blockedIPs = func() ([]string, error) { return nil, errors.New("db locked") }
	rr = httptest.NewRecorder()
	svc.handleBulkCommand(rr, bulkReq(t, `{"machine_ids":["m1"],"type":"sync-blocks"}`))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("unreadable list: status %d, want 500", rr.Code)
	}
}

// A sync-blocks without a list is refused, so it can never read as "empty the list".
func TestSyncBlocksNeedsList(t *testing.T) {
	for p, ok := range map[string]bool{``: false, `{}`: false, `{"ips":null}`: false, `{"ips":[]}`: true, `{"ips":["192.0.2.1"]}`: true} {
		if err := validateCommandPayload("sync-blocks", json.RawMessage(p)); (err == nil) != ok {
			t.Errorf("payload %q: err=%v, want ok=%v", p, err, ok)
		}
	}
}

// A dry-run command must say on or off: a missing value never reads as "off" (enforcing).
func TestSetDryRunNeedsValue(t *testing.T) {
	for p, ok := range map[string]bool{``: false, `{}`: false, `{"enabled":null}`: false, `{"enabled":false}`: true, `{"enabled":true}`: true} {
		if err := validateCommandPayload("set-dry-run", json.RawMessage(p)); (err == nil) != ok {
			t.Errorf("payload %q: err=%v, want ok=%v", p, err, ok)
		}
	}
}

// A targeted package fix carries plain package names only (never a flag or "name-", which apt
// reads as remove), and a bounded list.
func TestFixPackagesValidated(t *testing.T) {
	for p, ok := range map[string]bool{
		`{"packages":["openssl","libc6:amd64","g++"]}`: true,
		`{"packages":[]}`: false, `{}`: false, `{"packages":["nginx-"]}`: false,
		`{"packages":["--purge"]}`: false, `{"packages":["pkg=1.0"]}`: false,
	} {
		if err := validateCommandPayload("fix-packages", json.RawMessage(p)); (err == nil) != ok {
			t.Errorf("payload %s: err=%v, want ok=%v", p, err, ok)
		}
	}
}

// The single-command endpoint can't push a caller's list either: an empty list from the request
// is replaced by the panel's own.
func TestSingleSyncBlocksCarriesPanelList(t *testing.T) {
	svc := newTestService(t)
	addMachine(t, svc, "m1", true)
	svc.blockedIPs = func() ([]string, error) { return []string{"203.0.113.0/24"}, nil }
	body := `{"machine_id":"m1","type":"sync-blocks","payload":{"ips":[]}}`
	rr := httptest.NewRecorder()
	svc.handleEnqueueCommand(rr, asOwner(httptest.NewRequest(http.MethodPost, "/api/fleet/command", bytes.NewReader([]byte(body)))))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rr.Code, rr.Body.String())
	}
	var payload string
	if err := svc.db.QueryRow(`SELECT payload FROM fleet_commands WHERE machine_id='m1' AND type='sync-blocks'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if payload != `{"ips":["203.0.113.0/24"]}` {
		t.Fatalf("queued %s, want the panel's list", payload)
	}
}
