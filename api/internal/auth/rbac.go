package auth

// Role-based access control model.
//
// Roles are a strict privilege ladder: a higher role can do everything a lower one can.
// Enforcement of "what" a user may do is central (the router checks each endpoint's minimum
// role); enforcement of "which machines" a user may act on is the scope, applied in the fleet
// package. owner is the break-glass role — there is always at least one, and only an owner can
// mint or remove owners/admins.
const (
	RoleOwner    = "owner"    // full control, incl. managing admins/owners; cannot be the last one removed
	RoleAdmin    = "admin"    // full control except owner-only actions (managing owners/admins)
	RoleOperator = "operator" // day-to-day operational writes within scope; no user/security admin
	RoleViewer   = "viewer"   // read-only
)

// roleRank orders roles by privilege. 0 (absent) means "unknown role" and never satisfies a
// requirement — fail closed.
var roleRank = map[string]int{
	RoleViewer:   1,
	RoleOperator: 2,
	RoleAdmin:    3,
	RoleOwner:    4,
}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { return roleRank[r] > 0 }

// RoleAtLeast reports whether the have-role satisfies the min-role requirement. Both must be
// known roles, or it fails closed.
func RoleAtLeast(have, min string) bool {
	h, m := roleRank[have], roleRank[min]
	return h > 0 && m > 0 && h >= m
}

// Scope kinds bound which fleet machines a user may see and act on. owner/admin are implicitly
// unscoped (ScopeAll). An operator/viewer may be restricted to machines carrying a tag, or to
// an explicit set of machine IDs.
const (
	ScopeAll  = "all"  // every machine (the default)
	ScopeTag  = "tag"  // machines carrying any of the listed tags
	ScopeHost = "host" // the listed machine IDs only
)

// ValidScopeKind reports whether k is a known scope kind.
func ValidScopeKind(k string) bool {
	return k == ScopeAll || k == ScopeTag || k == ScopeHost
}
