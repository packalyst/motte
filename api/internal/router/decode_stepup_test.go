package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A handler that decodes its request and only then asks for a step-up (it needs the request to know
// whether the change loosens anything) must still hand the password to the step-up check.
func TestStepUpSeesPasswordAfterDecode(t *testing.T) {
	var seen string
	SetStepUpFunc(func(w http.ResponseWriter, r *http.Request) bool {
		var c struct {
			CurrentPassword string `json:"currentPassword"`
		}
		_ = json.NewDecoder(r.Body).Decode(&c)
		seen = c.CurrentPassword
		return c.CurrentPassword != ""
	})
	t.Cleanup(func() { SetStepUpFunc(nil) })

	r := httptest.NewRequest(http.MethodPut, "/x", strings.NewReader(`{"mode":"off","currentPassword":"pw"}`))
	var req struct {
		Mode string `json:"mode"`
	}
	if !DecodeJSONOrError(httptest.NewRecorder(), r, &req) || req.Mode != "off" {
		t.Fatalf("decode failed: %+v", req)
	}
	if !StepUp(httptest.NewRecorder(), r) || seen != "pw" {
		t.Fatalf("step-up after decode saw password %q", seen)
	}
}
