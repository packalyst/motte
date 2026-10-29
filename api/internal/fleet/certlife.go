package fleet

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// How long the machines' client certificates last (Settings → Agents), and when one may be renewed.

const (
	certDaysSetting = "fleet_cert_days"
	defaultCertDays = 90
)

// certDaysChoices are the lifetimes an admin can pick.
var certDaysChoices = []int{30, 60, 90, 180, 365}

// certDays is the configured lifetime in days (the default when unset or not a choice).
func (s *Service) certDays() int {
	d, err := strconv.Atoi(s.getSetting(certDaysSetting))
	if err != nil || !slices.Contains(certDaysChoices, d) {
		return defaultCertDays
	}
	return d
}

// clientCertTTL is what a new or renewed client certificate lasts.
func (s *Service) clientCertTTL() time.Duration {
	return time.Duration(s.certDays()) * 24 * time.Hour
}

// renewAllowed: a certificate may be renewed only in the last third of its own life (when the
// agent starts asking), plus a day for clock skew, so a stolen but valid certificate can't mint
// fresh ones ahead of time. Measured on the certificate itself, so a lifetime change applies to
// each machine from its next certificate.
func renewAllowed(c *x509.Certificate, now time.Time) bool {
	return c.NotAfter.Sub(now) <= c.NotAfter.Sub(c.NotBefore)/3+24*time.Hour
}

type certLifetimeRequest struct {
	Days            int    `json:"days"`
	CurrentPassword string `json:"currentPassword"`
	TotpCode        string `json:"totpCode"`
}

// handleCertLifetime: GET returns {"days", "choices"}; POST {"days"} sets it (admin, step-up). It
// applies to new and renewed certificates; existing ones keep their expiry.
func (s *Service) handleCertLifetime(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req certLifetimeRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
			router.JSONError(w, "invalid request", http.StatusBadRequest)
			return
		}
		if !slices.Contains(certDaysChoices, req.Days) {
			router.JSONError(w, "lifetime must be one of 30, 60, 90, 180 or 365 days", http.StatusBadRequest)
			return
		}
		if status, err := s.verifyStepUp(r, "change the machine certificate lifetime", req.CurrentPassword, req.TotpCode); err != nil {
			router.JSONError(w, err.Error(), status)
			return
		}
		if old := s.certDays(); old != req.Days {
			if err := s.setSettingsTx(map[string]string{certDaysSetting: strconv.Itoa(req.Days)}); err != nil {
				router.JSONError(w, "could not save", http.StatusInternalServerError)
				return
			}
			actor, _ := s.actingAdmin(r)
			events.Audit("fleet", "cert_lifetime_changed", events.SeverityInfo, actor, helper.GetClientIP(r),
				fmt.Sprintf("Machine certificate lifetime changed from %d to %d days (applies from each machine's next certificate)", old, req.Days))
		}
	}
	router.JSON(w, map[string]any{"days": s.certDays(), "choices": certDaysChoices})
}
