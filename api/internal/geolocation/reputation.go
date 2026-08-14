package geolocation

import (
	"fmt"
	"strings"
)

// Reputation levels (traffic-light buckets). Exported so callers can compare
// without hard-coding string literals.
const (
	RepUnknown = "unknown"
	RepLow     = "low"
	RepMedium  = "medium"
	RepHigh    = "high"
)

// Score thresholds separating the traffic-light buckets.
const (
	repMediumThreshold = 34
	repHighThreshold   = 67
)

// scoreReputation computes res.Reputation from the enrichment signals already
// set on res. proxyChecked reports whether the proxy DB was actually consulted:
// when it was, the *absence* of a proxy match is itself a (clean) signal, so we
// emit a "low" verdict; when it was not, we cannot judge and leave "unknown".
//
// Signals are objective and data-driven (fraud score, listed threat, proxy
// type, usage type). Deliberately excluded for now: country "risk" (subjective)
// and firewall hit-count (not available in the geo layer — the firewall can
// layer that on top of this base score later).
func scoreReputation(res *GeoResult, proxyChecked bool) {
	if res == nil {
		return
	}

	score := 0
	reasons := make([]string, 0, 4)

	if res.FraudScore != nil {
		score += int(*res.FraudScore) // 0-99, the dominant signal when present
		if *res.FraudScore > 0 {
			reasons = append(reasons, fmt.Sprintf("Fraud score %d/100", *res.FraudScore))
		}
	}

	if t := strings.TrimSpace(res.Threat); t != "" && t != "-" {
		score += 40
		reasons = append(reasons, "Listed threat: "+t)
	}

	if res.IsProxy {
		// Weight by how anonymizing the proxy type is.
		switch strings.ToUpper(strings.TrimSpace(res.ProxyType)) {
		case "TOR":
			score += 45
			reasons = append(reasons, "Tor exit node")
		case "PUB", "WEB":
			score += 35
			reasons = append(reasons, "Public / open proxy")
		case "VPN":
			score += 30
			reasons = append(reasons, "VPN service")
		case "DCH":
			score += 20
			reasons = append(reasons, "Data-center IP")
		default:
			score += 20
			reasons = append(reasons, "Proxy / anonymizer")
		}
	} else if strings.EqualFold(strings.TrimSpace(res.UsageType), "DCH") {
		// Hosting network but not flagged as a proxy — mildly risky.
		score += 15
		reasons = append(reasons, "Hosting / data-center network")
	}

	// No enrichment data was consulted at all — leave Reputation nil so the UI
	// renders nothing rather than a misleading zero-score verdict.
	if !proxyChecked && res.FraudScore == nil {
		return
	}

	if score > 100 {
		score = 100
	}

	var level string
	switch {
	case score >= repHighThreshold:
		level = RepHigh
	case score >= repMediumThreshold:
		level = RepMedium
	default:
		level = RepLow
		if len(reasons) == 0 {
			reasons = append(reasons, "Not a known proxy or VPN")
		}
	}

	res.Reputation = &Reputation{
		Score:   uint8(score),
		Level:   level,
		Reasons: reasons,
	}
}
