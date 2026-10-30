package firewall

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"api/internal/router"
)

// Clearing a whole list, or every rule of a source, takes a step-up: without one nothing goes.
func TestClearAllNeedsStepUp(t *testing.T) {
	s := lockoutService(t)
	if _, err := s.db.Exec(`INSERT INTO firewall_entries (entry_type, value, action, source) VALUES ('ip', '198.51.100.9', 'block', 'manual')`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Exec(`DELETE FROM firewall_entries WHERE value = '198.51.100.9'`) })
	router.SetStepUpFunc(func(w http.ResponseWriter, _ *http.Request) bool {
		w.WriteHeader(http.StatusPreconditionRequired)
		return false
	})
	t.Cleanup(func() { router.SetStepUpFunc(nil) })
	count := func() (n int) {
		s.db.QueryRow(`SELECT COUNT(*) FROM firewall_entries WHERE value = '198.51.100.9'`).Scan(&n)
		return
	}
	for _, c := range []struct {
		h    http.HandlerFunc
		path string
	}{{s.handleDeleteAll, "/api/fw/entries/all?action=block"}, {s.handleDeleteBySource, "/api/fw/entries/source/manual"}} {
		rr := httptest.NewRecorder()
		c.h(rr, httptest.NewRequest(http.MethodDelete, c.path, nil))
		if rr.Code != http.StatusPreconditionRequired || count() != 1 {
			t.Fatalf("%s without step-up: %d, %d left", c.path, rr.Code, count())
		}
	}
}
