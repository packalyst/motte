package pwa

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api/internal/database"
	"api/internal/router"
)

// Removing another device's notifications takes a step-up: without one it stays.
func TestRevokeOtherDeviceNeedsStepUp(t *testing.T) {
	db, _ := database.GetDB()
	if _, err := db.Exec(`DELETE FROM users_push_subscriptions; DELETE FROM users WHERE id = 7;
		INSERT INTO users (id, username, password_hash) VALUES (7, 'u7', 'x');
		INSERT INTO users_push_subscriptions (id, user_id, endpoint, key_p256dh, key_auth) VALUES (5, 7, 'https://fcm.googleapis.com/fcm/send/phone', 'k', 'a')`); err != nil {
		t.Fatal(err)
	}
	s := &Service{db: db}
	stepUpOK := false
	router.SetStepUpFunc(func(w http.ResponseWriter, _ *http.Request) bool {
		if !stepUpOK {
			w.WriteHeader(http.StatusPreconditionRequired)
		}
		return stepUpOK
	})
	t.Cleanup(func() { router.SetStepUpFunc(nil) })
	left := func() (n int) {
		db.QueryRow(`SELECT COUNT(*) FROM users_push_subscriptions`).Scan(&n)
		return
	}
	revoke := func() int {
		rr := httptest.NewRecorder()
		s.revokeSubscription(rr, httptest.NewRequest(http.MethodDelete, "/api/pwa/subscriptions?id=5", nil), 7)
		return rr.Code
	}
	if code := revoke(); code != http.StatusPreconditionRequired || left() != 1 {
		t.Fatalf("without step-up: %d, %d left", code, left())
	}
	stepUpOK = true
	if code := revoke(); code != http.StatusOK || left() != 0 {
		t.Fatalf("with step-up: %d, %d left", code, left())
	}
}

// The device list never carries an endpoint (with it any session could remove any device through
// POST /unsubscribe, skipping the step-up), only its fingerprint.
func TestSafeSubscriptionsHideEndpoint(t *testing.T) {
	const ep = "https://fcm.googleapis.com/fcm/send/secret-token"
	out, _ := json.Marshal(toSafeSubscriptions([]PushSubscription{{ID: 1, Endpoint: ep}}))
	if strings.Contains(string(out), "secret-token") {
		t.Fatalf("endpoint leaked: %s", out)
	}
	// SHA-256 of the endpoint, as the browser computes it to find its own row.
	if !strings.Contains(string(out), `"endpointHash":"`+endpointHash(ep)+`"`) || len(endpointHash(ep)) != 64 {
		t.Fatalf("missing fingerprint: %s", out)
	}
}
