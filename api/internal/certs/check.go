package certs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"api/internal/auth/pwa"
	"api/internal/events"
	"api/internal/routines"
)

// Start registers the daily expiry check (also run at start, so a restart never skips a day).
func (s *Service) Start() {
	routines.Register(routines.Spec{
		Name:        "cert-expiry-check",
		Description: "Warn admins about certificates close to expiry or failing to renew",
		Interval:    24 * time.Hour,
		RunAtStart:  true,
		Run:         s.check,
	})
}

// check sends each certificate's warning once per step it reaches: what was sent is kept in
// cert_alerts, so a restart doesn't repeat it, and a renewed certificate (new expiry) starts over.
// Rows for certificates that no longer exist are dropped.
func (s *Service) check(ctx context.Context) error {
	return s.checkList(trackedList(s.Overview(ctx)), time.Now())
}

func (s *Service) checkList(list []tracked, now time.Time) error {
	keep := make(map[string]bool, len(list))
	for _, t := range list {
		keep[t.key] = true
		level, due := currentLevel(t, now)
		if !due {
			continue
		}
		send, err := s.claim(t, level)
		if err != nil {
			return err
		}
		if send {
			s.warn(t, level)
		}
	}
	return s.prune(keep)
}

// claim records that a certificate reached level, reporting whether that's new: not sent yet for
// this certificate (same expiry) at this step or a lower one.
func (s *Service) claim(t tracked, level int) (bool, error) {
	notAfter := t.notAfter.UTC().Format(time.RFC3339)
	var storedAfter string
	var storedLevel int
	err := s.db.QueryRow(`SELECT not_after, level FROM cert_alerts WHERE cert_key = ?`, t.key).Scan(&storedAfter, &storedLevel)
	if err == nil && storedAfter == notAfter && storedLevel <= level {
		return false, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	_, err = s.db.Exec(`INSERT INTO cert_alerts (cert_key, not_after, level) VALUES (?, ?, ?)
		ON CONFLICT(cert_key) DO UPDATE SET not_after = excluded.not_after, level = excluded.level`, t.key, notAfter, level)
	return err == nil, err
}

// prune drops the rows of certificates that are gone (deleted machine, removed domain).
func (s *Service) prune(keep map[string]bool) error {
	rows, err := s.db.Query(`SELECT cert_key FROM cert_alerts`)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil && !keep[k] {
			gone = append(gone, k)
		}
	}
	rows.Close()
	for _, k := range gone {
		if _, err := s.db.Exec(`DELETE FROM cert_alerts WHERE cert_key = ?`, k); err != nil {
			return err
		}
	}
	return nil
}

// warnTitle is the warning's headline for a step.
func warnTitle(level int) string {
	switch level {
	case 0:
		return "Certificate expired"
	case 1:
		return "Certificate expires within a day"
	}
	return fmt.Sprintf("Certificate expires within %d days", level)
}

// warnAdmins logs the warning to Activity and notifies every admin and owner through their own
// channels (push, webhook, email), as their "Certificate expiring" preference allows.
func (s *Service) warnAdmins(t tracked, level int) {
	title := warnTitle(level)
	severity := events.SeverityWarning
	if level <= 3 {
		severity = events.SeverityCritical
	}
	events.Audit("certs", "cert_expiring", severity, "system", "", fmt.Sprintf("%s: %s (expires %s). %s", title, t.name, t.notAfter.UTC().Format(time.DateOnly), t.action))
	p := pwa.Get()
	if p == nil {
		return
	}
	ids, err := s.adminIDs()
	if err != nil {
		log.Printf("certs: listing admins: %v", err)
		return
	}
	for _, id := range ids {
		p.DispatchToUser(id, pwa.NotifyCertExpiry, &pwa.Notification{
			Title: title,
			Body:  t.name + ". " + t.action,
			Icon:  pwa.DefaultNotificationIcon,
			Tag:   "cert-" + t.key,
			Data:  map[string]string{"type": string(pwa.NotifyCertExpiry), "url": t.url},
		})
	}
}

// adminIDs lists the users certificate warnings go to: admins and owners only.
func (s *Service) adminIDs() ([]int64, error) {
	rows, err := s.db.Query(`SELECT id FROM users WHERE role IN ('admin', 'owner') ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
