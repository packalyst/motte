package helper

import "time"

// Every limit the panel enforces — how often, how many and how long — in one place, so "what are
// our limits?" is this file. Each is used where its feature lives; changing one here changes it
// there. Some can also be changed at run time, and then these are only the defaults: the jails
// (Settings → Firewall, seeded by firewall.ensureDefaultJails), the Traefik rate limits for proxied
// sites (Settings → Traefik), the API request rate (configs/endpoints.json) and the tunnel link
// guard (TURBOTUNNELS_ROTATE_* environment variables).

// Sign-in and re-authentication (package auth).
const (
	LoginMaxAttempts     = 5                // failed logins per client (an IPv6 client per /64) before a lockout
	LoginLockoutWindow   = 15 * time.Minute // the failures of login, 2FA and password re-checks are counted over this
	LoginLockoutDuration = 15 * time.Minute // and a lockout lasts this long
	TOTPMaxAttempts      = 5                // failed 2FA codes per user before a lockout
	PasswordMaxAttempts  = 5                // wrong passwords per user at step-up, unlock and password change
	MaxTrackedSignInKeys = 100_000          // clients or users each lockout tracks at once; past it the oldest is forgotten
	PasskeyChallengeTTL  = 3 * time.Minute  // a passkey registration or sign-in must finish within this
	MaxConcurrentArgon2  = 4                // password hashes computed at once, panel-wide (64 MiB each)
	// Failed password logins to one account from all clients together (a guess spread over many
	// addresses) before password login to it pauses. Only password login: passkeys and open
	// sessions keep working, so this can't lock the owner out of the panel.
	AccountLoginMaxAttempts = 50
	AccountLoginWindow      = time.Hour // counted over this
	AccountLoginPause       = time.Hour // and the pause lasts this long
)

// Settings → Preferences (packages auth and settings): the server accepts only these and the UI
// offers exactly these.
var (
	SessionTimeoutHours = []int{1, 8, 24, 168, 720} // how long a sign-in may last, in hours
	IdleLockMinutes     = []int{0, 5, 15, 30, 60}   // minutes without activity before the screen locks; 0 = never
)

// API requests (package router).
const (
	APIRequestsPerSecond  = 100     // per client, when configs/endpoints.json sets no rate
	APIBurstSeconds       = 2       // a client may burst this many seconds' worth of requests
	MaxRateLimitedClients = 100_000 // clients the request limiter tracks at once (an idle one drops out within the burst)
)

// Public tunnel links: /api/restart/{key} and /api/hook/{keys} (package turbotunnels).
const (
	TunnelKeyMaxFails       = 10               // wrong keys per client in TunnelKeyFailWindow before a block
	TunnelKeyFailWindow     = 5 * time.Minute  // the window those are counted in
	TunnelKeyBlockDuration  = 30 * time.Minute // how long a blocked client stays blocked
	TunnelRotateMinInterval = 10 * time.Second // between two rotations with one key
	MaxGuardedTunnelClients = 100_000          // clients the key guard tracks at once; past it the oldest is forgotten
	MaxThrottledTunnelKeys  = 10_000           // rotate keys and webhooks throttled at once (only valid ones get there)
)

// Fleet: the agent listener (package fleet).
const (
	FleetHeaderTimeout = 10 * time.Second // a request's headers must arrive within this
	FleetReadTimeout   = time.Minute      // its whole body within this
	FleetWriteTimeout  = time.Minute      // and it must take its answer within this
	FleetIdleTimeout   = time.Minute      // an idle keep-alive connection is closed after this
	FleetLargeTransfer = 10 * time.Minute // read and write time for a CVE report or the agent binary
	MaxFleetConnsPerIP = 256              // open connections per client address (a site of machines behind one NAT fits)
	AgentRequestBurst  = 30               // requests a machine may make at once
	AgentRequestRefill = time.Second      // then one more per this
	MaxAgentCerts      = 10_000           // machine certificates the request limiter tracks at once
	MaxReportBytes     = 1 << 20          // a status report
	MaxCVEReportBytes  = 64 << 20         // a CVE report, compressed and decompressed (one is stored at a time)
	MaxCVEFindings     = 200_000          // findings kept from one CVE report
	MaxFIMReportBytes  = 8 << 20          // a file-integrity report, decompressed
	MaxFIMEvents       = 5_000            // events kept from one file-integrity report
)

// Fleet: the browser console (package fleet).
const (
	MaxConsoleSessionsPerUser    = 10               // shells one user may have open on one machine
	MaxConsoleSessionsPerMachine = 30               // shells open on one machine, all users together
	MaxConsoleViewers            = 10               // browsers attached to one shell at once (the owner's tabs and read-only shares)
	ConsoleRecheck               = 30 * time.Second // an open console re-checks the user's access this often
	ConsoleIdleTimeout           = 30 * time.Minute // a shell idle this long is ended
	ConsoleMaxDuration           = 12 * time.Hour   // a shell open this long is ended
	ConsoleStepUpGrace           = 10 * time.Minute // after a password, fleet actions need no new one for this long (sliding)
	ConsoleStepUpGraceMax        = time.Hour        // but never longer than this after the password
	ConsoleGrantTTL              = 5 * time.Minute  // a console grant (after a password) opens consoles for this long...
	ConsoleGrantUses             = 50               // ...this many times (several tabs and reconnects)
	ConsoleShareGrantTTL         = 30 * time.Minute // a read-only share link works this long...
	ConsoleShareGrantUses        = 200              // ...this many times
	MaxConsoleGrants             = 100_000          // console grants alive at once, in all
	MaxConsoleGrantsPerUser      = 1_000            // and per user
	MaxConsoleGraceWindows       = 10_000           // sessions inside their grace window at once
	MaxRecordingBytes            = 64 << 20         // one session's recording; past it, output isn't recorded (marked once)
)

// Firewall: jails and the port-80 gate (package firewall). The other jails' defaults are in
// firewall.ensureDefaultJails.
const (
	WebGateJailMaxRetry   = 3        // port-80 drops from one address...
	WebGateJailFindTime   = 600      // ...within this many seconds...
	WebGateJailBanSeconds = 86400    // ...ban it for this long
	MaxJailTracked        = 100_000  // addresses one jail counts at once; past it the least recently seen is forgotten
	MaxJailFileBytes      = 5 << 20  // a file the panel writes for a jail starts over at this size
	MaxWebGateReportBytes = 64 << 10 // one report of port-80 drops from Traefik
	MaxWebGateDropsPerIP  = 10       // drops written per address per report
)

// Traffic accounting (package logs).
const (
	ConntrackFlowForget      = 30 * time.Minute // a flow not seen this long is forgotten (its close was missed)
	ConntrackDefaultMaxFlows = 262144           // flows tracked when the kernel's own limit can't be read
)
