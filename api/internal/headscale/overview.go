package headscale

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"api/internal/helper"
	"api/internal/router"
)

// keyListWorkers caps how many per-user key lists are asked of Headscale at once.
const keyListWorkers = 4

// fetchJSON gets a Headscale path and decodes it, keeping numbers exactly as sent.
func fetchJSON(path string) (map[string]any, error) {
	resp, err := helper.HeadscaleGet(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHeadscaleReply))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: headscale answered %s", path, resp.Status)
	}
	var v map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return v, nil
}

// fetchAll gets the paths at the same time; the first error wins.
func fetchAll(paths ...string) ([]map[string]any, error) {
	out := make([]map[string]any, len(paths))
	errs := make([]error, len(paths))
	var wg sync.WaitGroup
	for i, p := range paths {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			out[i], errs[i] = fetchJSON(p)
		}(i, p)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// list returns v[field] as a list (an absent or empty field is an empty list, never null).
func list(v map[string]any, field string) []any {
	if l, ok := v[field].([]any); ok {
		return l
	}
	return []any{}
}

// writeClean answers with reply after removing every join key from it (StripJoinKeys' rules).
func writeClean(w http.ResponseWriter, reply map[string]any) {
	dropJoinKeys(reply)
	router.JSON(w, reply)
}

// handleGetOverview answers the Headscale page in one reply: users, nodes and routes, plus which
// node is the panel's own router. Open to viewers, so it carries no keys at all (and the nodes'
// join keys are removed, as in every node reply).
func (s *Service) handleGetOverview(w http.ResponseWriter, r *http.Request) {
	res, err := fetchAll("/user", "/node", "/routes")
	if err != nil {
		headscaleUnreachable(w, err)
		return
	}
	writeClean(w, map[string]any{
		"users":       list(res[0], "users"),
		"nodes":       list(res[1], "nodes"),
		"routes":      list(res[2], "routes"),
		"panelRouter": map[string]string{"name": helper.GetRouterName(), "route": helper.GetEnv("WG_IP_RANGE")},
	})
}

// handleGetKeys answers the admin's key lists in one reply: every user's pre-auth keys (each shown
// by its prefix only) and the API keys (Headscale lists those by prefix already). Headscale 0.25
// lists pre-auth keys per user, so the users' lists are asked for here, a few at a time. A list that
// can't be read fails the whole reply: a partial list could hide a live key.
func (s *Service) handleGetKeys(w http.ResponseWriter, r *http.Request) {
	res, err := fetchAll("/user", "/apikey")
	if err != nil {
		headscaleUnreachable(w, err)
		return
	}
	users := list(res[0], "users")
	lists := make([][]any, len(users))
	errs := make([]error, len(users))
	sem := make(chan struct{}, keyListWorkers)
	var wg sync.WaitGroup
	for i, u := range users {
		m, _ := u.(map[string]any)
		name, _ := m["name"].(string)
		if name == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, name string) {
			defer func() { <-sem; wg.Done() }()
			v, err := fetchJSON("/preauthkey?user=" + url.QueryEscape(name))
			lists[i], errs[i] = list(v, "preAuthKeys"), err
		}(i, name)
	}
	wg.Wait()
	keys := []any{}
	for i, err := range errs {
		if err != nil {
			headscaleUnreachable(w, err)
			return
		}
		keys = append(keys, lists[i]...)
	}
	writeClean(w, map[string]any{"preAuthKeys": keys, "apiKeys": list(res[1], "apiKeys")})
}
