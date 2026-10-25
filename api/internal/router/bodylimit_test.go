package router

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"api/internal/config"
)

// An endpoint's max_body_mb raises the body limit for that path only; every other path keeps 10 MB.
func TestBodyLimitPerEndpoint(t *testing.T) {
	rt := New(&config.Config{Services: map[string]config.ServiceConfig{
		"files": {Prefix: "/api/files", Enabled: true, Endpoints: []config.EndpointConfig{
			{Path: "/big", Methods: []string{"POST"}, Handler: "Big", MaxBodyMB: 32},
			{Path: "/small", Methods: []string{"POST"}, Handler: "Small"},
		}},
	}})
	noop := func(http.ResponseWriter, *http.Request) {}
	rt.RegisterService("files", ServiceHandlers{"Big": noop, "Small": noop})
	rt.Build()
	if got := rt.bodyLimits["/api/files/big"]; got != 32<<20 {
		t.Fatalf("big limit = %d, want %d", got, 32<<20)
	}
	if _, ok := rt.bodyLimits["/api/files/small"]; ok {
		t.Fatal("small endpoint got its own limit")
	}

	readAll := rt.bodySizeLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		}
	}))
	body := bytes.Repeat([]byte("x"), 12<<20) // over 10 MB, under 32 MB
	for path, want := range map[string]int{"/api/files/big": http.StatusOK, "/api/files/small": http.StatusRequestEntityTooLarge, "/api/other": http.StatusRequestEntityTooLarge} {
		rec := httptest.NewRecorder()
		readAll.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
		if rec.Code != want {
			t.Errorf("%s: status %d, want %d", path, rec.Code, want)
		}
	}
}
