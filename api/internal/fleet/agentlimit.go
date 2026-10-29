package fleet

import (
	"time"

	"api/internal/bounded"
)

// Agent request limit. A machine normally makes a request every few seconds (reports, command
// polls, reconnects); a hacked one must not be able to keep the panel's database busy. Each client
// certificate gets a bucket of agentBurst requests that refills by one per agentRefill. It is
// checked before any database lookup. Only certificates our CA signed reach it, and a bucket is
// dropped once refilled, so maxAgentCerts is far above what a fleet uses at once.
const (
	agentBurst    = 30
	agentRefill   = time.Second
	maxAgentCerts = 10_000
)

var agentLimit = bounded.NewRate[string](maxAgentCerts, 1/agentRefill.Seconds(), agentBurst) // client-cert fingerprint
