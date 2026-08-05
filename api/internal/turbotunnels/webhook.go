package turbotunnels

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"api/internal/helper"
	"api/internal/router"
)

// webhookNextAllowed maps a webhook ID to the earliest time it may fire again —
// only populated for webhooks that set a min-interval. Guarded by rotMu (shared
// with rotate) and pruned by StartRotateGuardCleanup once entries expire, so it
// can't grow without bound.
var webhookNextAllowed = map[string]time.Time{}

// maxInboundBody caps how much of an inbound JSON body we read.
const maxInboundBody = 64 << 10

// handleWebhook is the PUBLIC webhook trigger: /api/hook/{keys...}. It validates
// every key in the path (all required), enforces the webhook's declared method
// and param contract, then forwards the validated params to the target URL —
// never exposing the URL or keys — and returns the target's response.
func (s *Service) handleWebhook(w http.ResponseWriter, r *http.Request) {
	// Cap the request body so a large POST can't balloon memory during parsing.
	r.Body = http.MaxBytesReader(w, r.Body, maxInboundBody)
	tail := router.ExtractPathParamFull(r, "/api/hook/")
	ip := helper.GetClientIP(r)

	if rotateBlocked(ip) {
		router.JSONError(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}

	cfg, err := LoadConfig()
	if err != nil {
		router.JSONError(w, "config error", http.StatusInternalServerError)
		return
	}

	// Find the webhook whose full key set matches the path tail. The keys are
	// joined with "/" and compared in constant time, which enforces the exact
	// count AND every key at once with no early-exit leak.
	var target *Webhook
	for ti := range cfg.Tunnels {
		for wi := range cfg.Tunnels[ti].Webhooks {
			wh := &cfg.Tunnels[ti].Webhooks[wi]
			if len(wh.Keys) == 0 {
				continue
			}
			want := strings.Join(wh.Keys, "/")
			if subtle.ConstantTimeCompare([]byte(want), []byte(tail)) == 1 {
				target = wh
				break
			}
		}
		if target != nil {
			break
		}
	}
	if target == nil {
		rotateRecordFail(ip)
		router.JSONError(w, "invalid key", http.StatusForbidden)
		return
	}

	// A valid key set clears this IP's brute-force streak. From here on, errors
	// are the caller's mistakes, not guessing, so they must NOT count as fails.
	rotateClearFails(ip)

	// Declared method only.
	if r.Method != target.Method {
		router.JSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read + validate the caller params against the declared contract.
	in, err := readInbound(r)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	params, err := validateInboundParams(target, in)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Per-webhook rate limit (0 = unlimited).
	if !webhookAllow(target) {
		router.JSONError(w, "rate limited, slow down", http.StatusTooManyRequests)
		return
	}

	code, body, err := callWebhook(target, params)
	if err != nil {
		router.JSONWithStatus(w, map[string]interface{}{"ok": false, "error": "forward failed"}, http.StatusBadGateway)
		return
	}
	resp := map[string]interface{}{"webhook": target.Name, "status": code, "response": formatProviderBody(body)}
	if code >= 200 && code < 400 {
		resp["ok"] = true
		router.JSON(w, resp)
		return
	}
	resp["ok"] = false
	router.JSONWithStatus(w, resp, http.StatusBadGateway)
}

// readInbound collects caller-supplied params from the query string plus either a
// form-encoded or JSON body, as url.Values (JSON scalars are stringified).
func readInbound(r *http.Request) (url.Values, error) {
	// Query params: treat '+' as a literal plus (RFC 3986 query semantics), so a
	// caller can send e.g. to=+40712345678 without percent-encoding. Go's default
	// query parsing would turn '+' into a space (a form-body convention).
	vals := parseQueryLiteralPlus(r.URL.RawQuery)

	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if strings.TrimSpace(ct) == "application/json" {
		body, _ := io.ReadAll(io.LimitReader(r.Body, maxInboundBody))
		if len(bytes.TrimSpace(body)) > 0 {
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.UseNumber() // keep numbers verbatim (e.g. a phone sent as a number)
			var m map[string]interface{}
			if err := dec.Decode(&m); err != nil {
				return nil, fmt.Errorf("invalid JSON body")
			}
			for k, v := range m {
				switch v.(type) {
				case nil:
					continue // JSON null == param absent
				case map[string]interface{}, []interface{}:
					return nil, fmt.Errorf("parameter %q must be a scalar", k)
				default:
					vals.Set(k, fmt.Sprintf("%v", v))
				}
			}
		}
		return vals, nil
	}

	// Form-encoded (or empty) body: merge the POST body values on top of the query.
	// Body '+' keeps its standard form-encoding meaning (space) — only the query
	// preserves a literal '+'.
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("bad request body")
	}
	for k, vs := range r.PostForm {
		for _, v := range vs {
			vals.Add(k, v)
		}
	}
	return vals, nil
}

// parseQueryLiteralPlus parses a raw URL query, treating '+' as a literal plus
// rather than a space. Falls back to standard parsing on error.
func parseQueryLiteralPlus(raw string) url.Values {
	if v, err := url.ParseQuery(strings.ReplaceAll(raw, "+", "%2B")); err == nil {
		return v
	}
	v, _ := url.ParseQuery(raw)
	return v
}

// validateInboundParams enforces the webhook's param contract: only declared
// params are allowed, and each must satisfy required/pattern/maxLen. Returns the
// clean set to forward.
func validateInboundParams(wh *Webhook, in url.Values) (map[string]string, error) {
	declared := make(map[string]WebhookParam, len(wh.Params))
	for _, p := range wh.Params {
		declared[p.Name] = p
	}
	// Reject anything not declared.
	for name := range in {
		if _, ok := declared[name]; !ok {
			return nil, fmt.Errorf("unknown parameter %q", name)
		}
	}
	out := make(map[string]string, len(wh.Params))
	for _, p := range wh.Params {
		v := strings.TrimSpace(in.Get(p.Name))
		if v == "" {
			if p.Required {
				return nil, fmt.Errorf("missing required parameter %q", p.Name)
			}
			continue
		}
		if p.MaxLen > 0 && len(v) > p.MaxLen {
			return nil, fmt.Errorf("parameter %q exceeds max length %d", p.Name, p.MaxLen)
		}
		if p.Pattern != "" {
			// Anchor both ends so the value must match in full regardless of
			// whether the admin's pattern is anchored (and without the
			// leftmost-first pitfall of FindStringIndex).
			re, err := regexp.Compile(`\A(?:` + p.Pattern + `)\z`)
			if err != nil || !re.MatchString(v) {
				return nil, fmt.Errorf("parameter %q does not match the required format", p.Name)
			}
		}
		out[p.Name] = v
	}
	return out, nil
}

// encodeQueryLiteralPlus encodes url.Values like Encode(), but emits '+' as a
// literal plus and a space as %20 (not '+'). This makes targets that read '+'
// literally (e.g. +CC phone numbers) get the right value, while spaces in free
// text (e.g. an SMS message) are not corrupted into '+'.
func encodeQueryLiteralPlus(v url.Values) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		ek := url.QueryEscape(k)
		for _, val := range v[k] {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			// QueryEscape maps space->'+' and '+'->%2B. Turn the space-'+' into
			// %20 first, then the escaped literal plus (%2B) back into '+'.
			ev := url.QueryEscape(val)
			ev = strings.ReplaceAll(ev, "+", "%20")
			ev = strings.ReplaceAll(ev, "%2B", "+")
			b.WriteString(ek)
			b.WriteByte('=')
			b.WriteString(ev)
		}
	}
	return b.String()
}

// webhookAllow enforces the per-webhook minimum interval. 0 = unlimited. Stores an
// expiry (next-allowed time) so the sweeper can evict lapsed entries.
func webhookAllow(wh *Webhook) bool {
	if wh.MinIntervalSec <= 0 {
		return true
	}
	rotMu.Lock()
	defer rotMu.Unlock()
	now := time.Now()
	if until, ok := webhookNextAllowed[wh.ID]; ok && now.Before(until) {
		return false
	}
	webhookNextAllowed[wh.ID] = now.Add(time.Duration(wh.MinIntervalSec) * time.Second)
	return true
}

// callWebhook forwards the validated params (plus the webhook's fixed values) to
// the target URL, using the declared method and encoding. Returns the target's
// status code and a capped copy of its body. Uses the redirect-refusing client
// shared with rotate (SSRF guard).
func callWebhook(wh *Webhook, params map[string]string) (int, string, error) {
	data := make(map[string]string, len(params)+len(wh.Fixed))
	for k, v := range params {
		data[k] = v
	}
	for k, v := range wh.Fixed { // fixed cannot collide with params (validated at save)
		data[k] = v
	}

	var req *http.Request
	var err error
	switch wh.Format {
	case "json":
		payload, _ := json.Marshal(data)
		req, err = http.NewRequest(wh.Method, wh.URL, bytes.NewReader(payload))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	case "form":
		vals := url.Values{}
		for k, v := range data {
			vals.Set(k, v)
		}
		req, err = http.NewRequest(wh.Method, wh.URL, strings.NewReader(vals.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	case "query":
		u, perr := url.Parse(wh.URL)
		if perr != nil {
			return 0, "", perr
		}
		q := u.Query()
		for k, v := range data {
			q.Set(k, v)
		}
		u.RawQuery = encodeQueryLiteralPlus(q)
		req, err = http.NewRequest(wh.Method, u.String(), nil)
	default:
		return 0, "", fmt.Errorf("unsupported format")
	}
	if err != nil {
		return 0, "", err
	}

	resp, err := rotateHTTPClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, strings.TrimSpace(string(b)), nil
}
