package clients

// Per-client ad & tracker blocking (AdGuard). Admin only — the blocked-query list is browsing
// history. The client is named by its key in the path; its address is always looked up here, never
// taken from the request. Every change is audited.
//
//   GET    /api/clients/{key}/adblock          state, recent blocked lookups, allowed domains
//   PUT    /api/clients/{key}/adblock          {"blocking": bool}
//   POST   /api/clients/{key}/adblock/allow    {"domain": "..."}
//   DELETE /api/clients/{key}/adblock/allow?domain=...

import (
	"errors"
	"log"
	"net/http"
	"time"

	"api/internal/adguard"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

const (
	recentBlocked  = 20
	adguardSyncDur = 5 * time.Minute
)

// adblockClient resolves the {key} path segment to a VPN client or LAN device. Machines aren't
// offered: they normally use their own DNS, not the panel's.
func (s *Service) adblockClient(w http.ResponseWriter, r *http.Request) (Client, bool) {
	key := router.ExtractPathParam(r, "/api/clients")
	if !adguard.ValidKey(key) {
		router.JSONError(w, "unknown client", http.StatusNotFound)
		return Client{}, false
	}
	list, _ := s.build(nil, nil)
	for _, c := range list {
		if c.Key == key {
			if c.IP == "" {
				router.JSONError(w, "this client has no address yet", http.StatusConflict)
				return Client{}, false
			}
			return c, true
		}
	}
	router.JSONError(w, "unknown client", http.StatusNotFound)
	return Client{}, false
}

// adguardError maps AdGuard failures: a conflict the admin can resolve, or AdGuard unreachable
// (details logged, not returned).
func adguardError(w http.ResponseWriter, err error) {
	if errors.Is(err, adguard.ErrManagedElsewhere) {
		router.JSONError(w, err.Error(), http.StatusConflict)
		return
	}
	log.Printf("clients: adguard: %v", err)
	router.JSONError(w, "AdGuard request failed — check that AdGuard is running and its credentials in Settings", http.StatusFailedDependency)
}

func audit(r *http.Request, event, msg string) {
	actor := ""
	if p := router.CurrentUser(r); p != nil {
		actor = p.Username
	}
	events.Audit("adguard", event, events.SeverityInfo, actor, helper.GetClientIP(r), msg)
}

func (s *Service) handleAdblockGet(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adblockClient(w, r)
	if !ok {
		return
	}
	st, err := adguard.ClientBlocking(c.Key, c.IP)
	if err != nil {
		adguardError(w, err)
		return
	}
	blocked, err := adguard.RecentBlocked(c.IP, recentBlocked)
	if err != nil {
		adguardError(w, err)
		return
	}
	allowed, err := adguard.AllowedForClient(c.Key, c.IP)
	if err != nil {
		adguardError(w, err)
		return
	}
	router.JSON(w, map[string]any{"state": st, "blocked": blocked, "allowed": allowed, "ip": c.IP})
}

func (s *Service) handleAdblockSet(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adblockClient(w, r)
	if !ok {
		return
	}
	var req struct {
		Blocking *bool `json:"blocking"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if req.Blocking == nil {
		router.JSONError(w, "blocking is required", http.StatusBadRequest)
		return
	}
	if err := adguard.SetClientBlocking(c.Key, c.IP, *req.Blocking); err != nil {
		adguardError(w, err)
		return
	}
	word := "off"
	if *req.Blocking {
		word = "on"
	}
	audit(r, "client_adblock", "Ad & tracker blocking "+word+" for "+c.Name+" ("+c.IP+")")
	router.JSON(w, map[string]bool{"blocking": *req.Blocking})
}

func (s *Service) handleAdblockAllow(w http.ResponseWriter, r *http.Request) {
	c, ok := s.adblockClient(w, r)
	if !ok {
		return
	}
	var domain string
	allow := r.Method == http.MethodPost
	if allow {
		var req struct {
			Domain string `json:"domain"`
		}
		if !router.DecodeJSONOrError(w, r, &req) {
			return
		}
		domain = req.Domain
	} else {
		domain = r.URL.Query().Get("domain")
	}
	d, err := adguard.NormalizeDomain(domain)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := adguard.SetAllowed(c.Key, c.IP, d, allow); err != nil {
		adguardError(w, err)
		return
	}
	if allow {
		audit(r, "client_adblock_allow", "Allowed "+d+" for "+c.Name+" ("+c.IP+")")
	} else {
		audit(r, "client_adblock_disallow", "Removed the "+d+" exception for "+c.Name+" ("+c.IP+")")
	}
	router.JSON(w, map[string]any{"domain": d, "allowed": allow})
}

// syncAdGuard keeps the panel's AdGuard entries in step with the clients (gone → removed, moved
// → updated). It only runs on a complete list: a source that failed to load must not make its
// clients look deleted.
func (s *Service) syncAdGuard() {
	if adguard.GetService() == nil { // AdGuard service turned off in this install
		return
	}
	list, unavailable := s.build(nil, nil)
	for _, u := range unavailable {
		if u != "Machines" { // machines aren't part of this
			return
		}
	}
	current := map[string]string{}
	for _, c := range list {
		if adguard.ValidKey(c.Key) {
			current[c.Key] = c.IP
		}
	}
	if err := adguard.SyncManaged(current); err != nil {
		log.Printf("clients: adguard sync: %v", err)
	}
}

// SyncAdGuard runs syncAdGuard now and then every adguardSyncDur.
func (s *Service) SyncAdGuard() {
	go func() {
		for {
			s.syncAdGuard()
			time.Sleep(adguardSyncDur)
		}
	}()
}
