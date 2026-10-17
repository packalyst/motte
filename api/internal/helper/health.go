package helper

import "sync/atomic"

// firewallActive reports whether the nftables/firewall layer came up at boot. It defaults to
// true (the healthy / firewall-disabled-by-config case) and main flips it to false when the
// firewall is enabled but failed to initialize — so the UI can warn that the gate is NOT being
// managed, instead of that state hiding in a boot log line.
var firewallActive atomic.Bool

func init() { firewallActive.Store(true) }

// SetFirewallActive records whether the firewall layer is active (called once at boot).
func SetFirewallActive(ok bool) { firewallActive.Store(ok) }

// FirewallActive reports the last value set by SetFirewallActive.
func FirewallActive() bool { return firewallActive.Load() }
