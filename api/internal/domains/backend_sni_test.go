package domains

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Naming the domain to an HTTPS backend is stored, read back and written to Traefik, and
// switching it off takes the hostname out again.
func TestRouteBackendSNI(t *testing.T) {
	db, _ := lanFixture(t)
	RoutesApplied = func() {}
	s := New()
	call := func(h http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(method, path, strings.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s %s %s: %d %s", method, path, body, rr.Code, rr.Body)
		}
		return rr
	}
	routesFile := func() string {
		b, _ := os.ReadFile(filepath.Join(os.Getenv("TRAEFIK_CONFIG"), "domains.yml"))
		return string(b)
	}

	call(s.handleCreate, http.MethodPost, "/api/domains", `{"domain":"tax.example.com","targetIp":"10.8.0.9","targetPort":443,"httpsBackend":true,"backendSni":true}`)
	var id int
	db.QueryRow(`SELECT id FROM domain_routes WHERE domain = 'tax.example.com'`).Scan(&id)
	path := fmt.Sprintf("/api/domains/%d", id)

	var got DomainRoute
	if err := json.Unmarshal(call(s.handleGet, http.MethodGet, path, "").Body.Bytes(), &got); err != nil || !got.BackendSNI {
		t.Fatalf("read back: %+v %v", got, err)
	}
	if f := routesFile(); !strings.Contains(f, `serverName: "tax.example.com"`) {
		t.Fatalf("Traefik must name the domain to the backend:\n%s", f)
	}

	call(s.handleUpdate, http.MethodPut, path, `{"backendSni":false}`)
	if f := routesFile(); strings.Contains(f, "serverName") {
		t.Fatalf("switched off, the hostname must be gone:\n%s", f)
	}
}
