package turbotunnels

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/settings"
)

// guardCall sends one request for path through h from addr and returns the status.
func guardCall(h http.HandlerFunc, path, addr string) int {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = addr
	h(rec, req)
	return rec.Code
}

// Guessing keys from new addresses inside one IPv6 /64 still trips the block, on both public
// doors; another /64 is unaffected.
func TestGuardGroupsIPv6(t *testing.T) {
	s := &Service{}
	for i, door := range []struct {
		h    http.HandlerFunc
		path string
	}{{s.handleRotate, "/api/restart/wrong-key"}, {s.handleWebhook, "/api/hook/wrong-key"}} {
		net := fmt.Sprintf("2001:db8:%x:7", i)
		for n := 0; n < rotateFailThreshold(); n++ {
			if c := guardCall(door.h, door.path, fmt.Sprintf("[%s::%x]:1000", net, n+1)); c != http.StatusForbidden {
				t.Fatalf("%s: guess %d: %d", door.path, n+1, c)
			}
		}
		if c := guardCall(door.h, door.path, fmt.Sprintf("[%s:ffff::1]:1000", net)); c != http.StatusTooManyRequests {
			t.Fatalf("%s: a new address in the same /64 kept guessing: %d", door.path, c)
		}
		if c := guardCall(door.h, door.path, fmt.Sprintf("[2001:db8:%x:8::1]:1000", i)); c != http.StatusForbidden {
			t.Fatalf("%s: another /64 was blocked: %d", door.path, c)
		}
	}
}

// A valid key clears the client's wrong guesses, on both doors.
func TestGuardValidKeyClears(t *testing.T) {
	t.Setenv("ENCRYPTION_SECRET", strings.Repeat("ab", 32)) // synthetic test key
	helper.InitEncryption()
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := settings.SetSettingEncrypted(settingKeyConfig, `{"tunnels":[{"name":"t","rotateUrl":"http://127.0.0.1:1/","rotateKey":"good-rotate-key",
		"webhooks":[{"id":"w","method":"GET","keys":["good-hook-key"],"url":"http://127.0.0.1:1/"}]}]}`); err != nil {
		t.Fatal(err)
	}
	s := &Service{}
	for i, door := range []struct {
		h          http.HandlerFunc
		bad, valid string
	}{{s.handleRotate, "/api/restart/wrong-key", "/api/restart/good-rotate-key"}, {s.handleWebhook, "/api/hook/wrong-key", "/api/hook/good-hook-key"}} {
		addr := fmt.Sprintf("192.0.2.%d:1000", 40+i)
		for n := 0; n < rotateFailThreshold()-1; n++ {
			guardCall(door.h, door.bad, addr)
		}
		if c := guardCall(door.h, door.valid, addr); c == http.StatusForbidden || c == http.StatusTooManyRequests {
			t.Fatalf("%s: valid key refused: %d", door.valid, c)
		}
		for n := 0; n < rotateFailThreshold(); n++ {
			if c := guardCall(door.h, door.bad, addr); c != http.StatusForbidden {
				t.Fatalf("%s: guess %d after a valid key: %d", door.bad, n+1, c)
			}
		}
	}
}

// A rotate key fires at most once per interval; a webhook's interval is given back when its
// forward failed.
func TestThrottles(t *testing.T) {
	t.Setenv("ENCRYPTION_SECRET", strings.Repeat("ab", 32)) // synthetic test key
	helper.InitEncryption()
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := settings.SetSettingEncrypted(settingKeyConfig, `{"tunnels":[{"name":"t","rotateUrl":"http://127.0.0.1:1/","rotateKey":"throttled-key"}]}`); err != nil {
		t.Fatal(err)
	}
	s := &Service{}
	if c := guardCall(s.handleRotate, "/api/restart/throttled-key", "192.0.2.50:1000"); c == http.StatusTooManyRequests {
		t.Fatal("first rotation throttled")
	}
	if c := guardCall(s.handleRotate, "/api/restart/throttled-key", "192.0.2.51:1000"); c != http.StatusTooManyRequests {
		t.Fatalf("second rotation within the interval: %d", c)
	}

	wh := &Webhook{ID: "throttled-hook", MinIntervalSec: 60}
	if !webhookAllow(wh) || webhookAllow(wh) {
		t.Fatal("webhook not limited to once per interval")
	}
	webhookRefund(wh)
	if !webhookAllow(wh) {
		t.Fatal("a refunded interval still throttles")
	}
	if !webhookAllow(&Webhook{ID: "unlimited"}) || !webhookAllow(&Webhook{ID: "unlimited"}) {
		t.Fatal("a webhook without an interval was throttled")
	}
}

// A request that fails on the panel's side (unreadable config) isn't counted as a wrong guess.
func TestGuardConfigErrorNotCounted(t *testing.T) {
	t.Setenv("ENCRYPTION_SECRET", strings.Repeat("ab", 32)) // synthetic test key
	helper.InitEncryption()
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := settings.SetSettingEncrypted(settingKeyConfig, `not json`); err != nil {
		t.Fatal(err)
	}
	s := &Service{}
	for n := 0; n <= rotateFailThreshold(); n++ {
		if c := guardCall(s.handleRotate, "/api/restart/any", "192.0.2.52:1000"); c != http.StatusInternalServerError {
			t.Fatalf("request %d: %d, want 500", n+1, c)
		}
		if c := guardCall(s.handleWebhook, "/api/hook/any", "192.0.2.53:1000"); c != http.StatusInternalServerError {
			t.Fatalf("webhook request %d: %d, want 500", n+1, c)
		}
	}
}
