package fleet

import (
	"net/http"
	"testing"
)

// One CVE report is stored at a time: while one is in progress another is refused with 503 (the
// agent sends it again), and once the slot is free a report goes through.
func TestCVEReportOneAtATime(t *testing.T) {
	svc := newTestService(t)
	_, cert := enrolledMachine(t, svc)
	report := []byte(`{"scanned_at":"2026-01-02T03:04:05Z","trigger":"manual","findings":[{"id":"CVE-2026-0001","pkg":"examplepkg","installed":"1.0","severity":"HIGH","target":"debian 12","class":"os-pkgs","type":"debian"}]}`)

	cveIngestSlot <- struct{}{} // a report is being stored
	rr := callAs(svc, svc.HandleCVEReport, cert, report)
	<-cveIngestSlot
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("second report while one is stored: %d %q", rr.Code, rr.Header().Get("Retry-After"))
	}
	if rr := callAs(svc, svc.HandleCVEReport, cert, report); rr.Code != http.StatusOK {
		t.Fatalf("report with the slot free: %d %s", rr.Code, rr.Body)
	}
	select {
	case cveIngestSlot <- struct{}{}:
		<-cveIngestSlot
	default:
		t.Fatal("the slot wasn't released after the report")
	}
}
