package fleet

import (
	"api/internal/bounded"
	"api/internal/helper"
)

// Agent request limit. A machine normally makes a request every few seconds (reports, command
// polls, reconnects); a hacked one must not be able to keep the panel's database busy. Each client
// certificate gets a bucket of helper.AgentRequestBurst requests that refills by one per
// helper.AgentRequestRefill. It is checked before any database lookup. Only certificates our CA
// signed reach it, and a bucket is dropped once refilled, so helper.MaxAgentCerts is far above what
// a fleet uses at once.
var agentLimit = bounded.NewRate[string](helper.MaxAgentCerts, 1/helper.AgentRequestRefill.Seconds(), helper.AgentRequestBurst) // client-cert fingerprint
