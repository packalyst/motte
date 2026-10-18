package fleet

import (
	"net/http"

	"api/internal/auth"
	"api/internal/router"
)

// Machine scoping. A user's role decides WHAT they may do (enforced centrally by the router);
// their scope decides WHICH machines. owner/admin are always unscoped; an operator/viewer may
// be limited to an explicit set of machine IDs (host scope) or to machines carrying one of a
// set of tags (tag scope). Scope is enforced here, in the fleet package, on every endpoint
// that reads or acts on a specific machine, plus as a filter on the machine list.

// scopeAllows reports whether principal p may access machine m.
func scopeAllows(p *router.Principal, m Machine) bool {
	if p == nil {
		return false
	}
	// owner/admin, or an explicit "all" scope, see everything.
	if auth.RoleAtLeast(p.Role, auth.RoleAdmin) || p.ScopeKind == "" || p.ScopeKind == auth.ScopeAll {
		return true
	}
	values := splitTags(p.ScopeValues) // reuse the CSV splitter (ids or tags)
	switch p.ScopeKind {
	case auth.ScopeHost:
		for _, id := range values {
			if id == m.ID {
				return true
			}
		}
	case auth.ScopeTag:
		have := map[string]bool{}
		for _, t := range m.Tags {
			have[t] = true
		}
		for _, want := range values {
			if have[want] {
				return true
			}
		}
	}
	return false
}

// machineAllowed reports whether the request's principal may access machineID, loading the
// machine's tags only when the scope is tag-based.
func (s *Service) machineAllowed(r *http.Request, machineID string) bool {
	p := router.CurrentUser(r)
	if p == nil {
		return false
	}
	if auth.RoleAtLeast(p.Role, auth.RoleAdmin) || p.ScopeKind == "" || p.ScopeKind == auth.ScopeAll {
		return true
	}
	var tags []string
	if p.ScopeKind == auth.ScopeTag {
		t, err := s.machineTags(machineID)
		if err != nil {
			return false
		}
		tags = t
	}
	return scopeAllows(p, Machine{ID: machineID, Tags: tags})
}

// requireMachineAccess enforces machineAllowed; on denial it writes 403 and returns false so
// the handler returns without acting.
func (s *Service) requireMachineAccess(w http.ResponseWriter, r *http.Request, machineID string) bool {
	if !s.machineAllowed(r, machineID) {
		writeErr(w, http.StatusForbidden, "your scope does not include this machine")
		return false
	}
	return true
}

// filterMachines returns only the machines the request's principal is scoped to see.
func (s *Service) filterMachines(r *http.Request, machines []Machine) []Machine {
	p := router.CurrentUser(r)
	if p == nil {
		return nil
	}
	if auth.RoleAtLeast(p.Role, auth.RoleAdmin) || p.ScopeKind == "" || p.ScopeKind == auth.ScopeAll {
		return machines
	}
	out := []Machine{}
	for _, m := range machines {
		if scopeAllows(p, m) {
			out = append(out, m)
		}
	}
	return out
}
