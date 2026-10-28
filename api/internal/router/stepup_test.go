package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStepUpLeavesBodyForHandler: the step-up check reads the password from the body, and the
// handler still decodes its own fields from the same body afterwards (changing the SSH port,
// creating keys).
func TestStepUpLeavesBodyForHandler(t *testing.T) {
	prev := stepUpFn
	t.Cleanup(func() { stepUpFn = prev })
	stepUpFn = func(w http.ResponseWriter, r *http.Request) bool {
		var creds struct {
			CurrentPassword string `json:"currentPassword"`
		}
		_ = json.NewDecoder(r.Body).Decode(&creds)
		return creds.CurrentPassword == "synthetic-password"
	}

	r := httptest.NewRequest(http.MethodPost, "/api/fw/ssh", strings.NewReader(`{"port":2222,"currentPassword":"synthetic-password"}`))
	if !StepUp(httptest.NewRecorder(), r) {
		t.Fatal("step-up refused the right password")
	}
	var req struct {
		Port int `json:"port"`
	}
	if !DecodeJSONOrError(httptest.NewRecorder(), r, &req) || req.Port != 2222 {
		t.Fatalf("handler could not read its body after step-up: port %d", req.Port)
	}
}
