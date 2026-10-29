package fleet

import (
	"sync"
	"time"
)

// Agent request limit. A machine normally makes a request every few seconds (reports, command
// polls, reconnects); a hacked one must not be able to keep the panel's database busy. Each client
// certificate gets a bucket of agentBurst requests that refills by one per agentRefill. It is
// checked before any database lookup.
const (
	agentBurst  = 30
	agentRefill = time.Second
)

type agentBucket struct {
	tokens float64
	last   time.Time
}

var (
	agentMu      sync.Mutex
	agentBuckets = map[string]*agentBucket{} // client-cert fingerprint → bucket
)

// agentAllowed takes one request from the certificate's bucket, or reports it's empty.
func agentAllowed(fp string, now time.Time) bool {
	agentMu.Lock()
	defer agentMu.Unlock()
	if len(agentBuckets) > 4096 { // only certs our CA signed reach here; drop long-idle ones
		for k, b := range agentBuckets {
			if now.Sub(b.last) > time.Hour {
				delete(agentBuckets, k)
			}
		}
	}
	b, ok := agentBuckets[fp]
	if !ok {
		b = &agentBucket{tokens: agentBurst, last: now}
		agentBuckets[fp] = b
	}
	b.tokens += float64(now.Sub(b.last)) / float64(agentRefill)
	if b.tokens > agentBurst {
		b.tokens = agentBurst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
