package headscale

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"api/internal/database"
	"api/internal/domains"
	"api/internal/events"
	"api/internal/helper"
	"api/internal/router"
)

// ===========================================
// Exported API functions (for use by vpn/router.go)
// ===========================================

// User represents a Headscale user
type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Node represents a Headscale node
type Node struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	GivenName   string   `json:"givenName"`
	IPAddresses []string `json:"ipAddresses"`
	User        User     `json:"user"`
}

// Route represents a Headscale route
type Route struct {
	ID      string `json:"id"`
	Prefix  string `json:"prefix"`
	Enabled bool   `json:"enabled"`
	Node    Node   `json:"node"`
}

// getUserIDByName looks up a Headscale user ID by name (internal)
func getUserIDByName(name string) (string, error) {
	var result struct {
		Users []User `json:"users"`
	}
	if err := helper.HeadscaleGetJSON("/user", &result); err != nil {
		return "", err
	}
	for _, user := range result.Users {
		if user.Name == name {
			return user.ID, nil
		}
	}
	return "", fmt.Errorf("user '%s' not found", name)
}

// CreateUser creates a new Headscale user
func CreateUser(name string) error {
	// Build the body with json.Marshal (never string-format) so a name with a
	// quote/backslash can't break out of or inject into the JSON.
	b, _ := json.Marshal(map[string]string{"name": name})
	resp, err := helper.HeadscalePost("/user", string(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		respBody, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(respBody), "already exists") {
			return nil // User exists, that's fine
		}
		return fmt.Errorf("failed to create user: %s", string(respBody))
	}
	return nil
}

// DeleteUser deletes a Headscale user by name
func DeleteUser(name string) error {
	userID, err := getUserIDByName(name)
	if err != nil {
		// User not found is not an error for deletion
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return err
	}

	resp, err := helper.HeadscaleDelete("/user/" + userID)
	if err != nil {
		return err
	}
	resp.Body.Close()
	log.Printf("Deleted Headscale user %s (ID: %s)", name, userID)
	return nil
}

// DeleteNode deletes a Headscale node by ID
func DeleteNode(nodeID string) error {
	resp, err := helper.HeadscaleDelete("/node/" + nodeID)
	if err != nil {
		return err
	}
	resp.Body.Close()
	log.Printf("Deleted Headscale node %s", nodeID)
	return nil
}

// ExpireNode expires a Headscale node by ID
func ExpireNode(nodeID string) error {
	resp, err := helper.HeadscalePost("/node/"+nodeID+"/expire", "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	log.Printf("Expired Headscale node %s", nodeID)
	return nil
}

// ExpireAllNodes expires all Headscale nodes, returns count of expired nodes
func ExpireAllNodes() (int, error) {
	nodes, err := GetNodes()
	if err != nil {
		return 0, err
	}

	expired := 0
	for _, node := range nodes {
		if err := ExpireNode(node.ID); err != nil {
			log.Printf("Warning: failed to expire node %s: %v", node.ID, err)
			continue
		}
		expired++
	}
	return expired, nil
}

// CreatePreAuthKey creates a pre-auth key for a user
func CreatePreAuthKey(user string, reusable, ephemeral bool, expiration time.Time) (string, error) {
	payload, err := json.Marshal(map[string]interface{}{
		"user":       user,
		"reusable":   reusable,
		"ephemeral":  ephemeral,
		"expiration": expiration.Format(time.RFC3339),
	})
	if err != nil {
		return "", fmt.Errorf("failed to build request: %v", err)
	}
	body := string(payload)

	log.Printf("Creating pre-auth key for user %s, expiration: %s", user, expiration.Format(time.RFC3339))

	resp, err := helper.HeadscalePost("/preauthkey", body)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return "", fmt.Errorf("failed to create pre-auth key (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		PreAuthKey struct {
			Key string `json:"key"`
		} `json:"preAuthKey"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %v, body: %s", err, string(respBody))
	}

	if result.PreAuthKey.Key == "" {
		return "", fmt.Errorf("empty key in response: %s", string(respBody))
	}

	return result.PreAuthKey.Key, nil
}

// GetNodes returns all Headscale nodes
func GetNodes() ([]Node, error) {
	var result struct {
		Nodes []Node `json:"nodes"`
	}
	if err := helper.HeadscaleGetJSON("/node", &result); err != nil {
		return nil, err
	}
	return result.Nodes, nil
}

// GetRoutes returns all Headscale routes
func GetRoutes() ([]Route, error) {
	var result struct {
		Routes []Route `json:"routes"`
	}
	if err := helper.HeadscaleGetJSON("/routes", &result); err != nil {
		return nil, err
	}
	return result.Routes, nil
}

// GetNodeRoutes returns routes for a specific node
func GetNodeRoutes(nodeID string) ([]Route, error) {
	var result struct {
		Routes []Route `json:"routes"`
	}
	if err := helper.HeadscaleGetJSON("/node/"+nodeID+"/routes", &result); err != nil {
		return nil, err
	}
	return result.Routes, nil
}

// EnableRoute enables a route by ID
func EnableRoute(routeID string) error {
	resp, err := helper.HeadscalePost("/routes/"+routeID+"/enable", "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to enable route: status %d", resp.StatusCode)
	}
	return nil
}

// ===========================================

// validName matches valid Headscale user/node names (alphanumeric, underscore, dash)
var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// validNodeID matches valid Headscale node IDs (numeric only)
var validNodeID = regexp.MustCompile(`^[0-9]+$`)

// Service handles Headscale operations
type Service struct{}

// New creates a new Headscale service
func New() *Service {
	log.Printf("Headscale service initialized")
	return &Service{}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetUsers":         s.handleGetUsers,
		"CreateUser":       s.handleCreateUser,
		"DeleteUser":       s.handleDeleteUser,
		"RenameUser":       s.handleRenameUser,
		"GetOverview":      s.handleGetOverview,
		"GetKeys":          s.handleGetKeys,
		"GetNodes":         s.handleGetNodes,
		"DeleteNode":       s.handleDeleteNode,
		"RenameNode":       s.handleRenameNode,
		"ExpireNode":       s.handleExpireNode,
		"UpdateNodeTags":   s.handleUpdateNodeTags,
		"GetRoutes":        s.handleGetRoutes,
		"EnableRoute":      s.handleEnableRoute,
		"DisableRoute":     s.handleDisableRoute,
		"DeleteRoute":      s.handleDeleteRoute,
		"CreatePreAuthKey": s.handleCreatePreAuthKey,
		"ExpirePreAuthKey": s.handleExpirePreAuthKey,
		"CreateAPIKey":     s.handleCreateAPIKey,
		"DeleteAPIKey":     s.handleDeleteAPIKey,
	}
}

// --- HTTP helpers ---

// proxyResponse writes the Headscale response to the client
// maxHeadscaleReply bounds a reply read whole to strip its join keys.
const maxHeadscaleReply = 8 << 20

// proxyResponse relays a Headscale reply for path with its join keys removed (StripJoinKeys):
// Headscale 0.25 reports each node, and each route's node, with the full key it joined with, and the
// node and route lists are open to viewers. The one reply that keeps its key is a newly created
// key's (handleCreatePreAuthKey): it's shown once, then only its prefix.
func (s *Service) proxyResponse(w http.ResponseWriter, resp *http.Response, path string) {
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHeadscaleReply))
	if err == nil {
		body, err = StripJoinKeys(body)
	}
	if err != nil { // never relay a reply we couldn't clean
		log.Printf("headscale: unreadable reply from %s: %v", path, err)
		router.JSONError(w, "unexpected reply from Headscale", http.StatusBadGateway)
		return
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// keyPrefixLen is how much of a pre-auth key the key list shows, enough to tell keys apart.
const keyPrefixLen = 12

// StripJoinKeys removes the join keys from a Headscale JSON reply, at any depth: every "preAuthKey"
// (a node's, a route's node's) is dropped, and in a "preAuthKeys" list each key is replaced by its
// first keyPrefixLen characters ("keyPrefix"). An empty body is returned as is.
func StripJoinKeys(body []byte) ([]byte, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return body, nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // keep numbers exactly as Headscale sent them
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	dropJoinKeys(v)
	return json.Marshal(v)
}

// maskKey replaces a key entry's "key" with its prefix.
func maskKey(entry map[string]any) {
	k, ok := entry["key"].(string)
	if !ok {
		return
	}
	delete(entry, "key")
	if len(k) > keyPrefixLen {
		k = k[:keyPrefixLen]
	}
	entry["keyPrefix"] = k
}

func dropJoinKeys(v any) {
	switch t := v.(type) {
	case map[string]any:
		delete(t, "preAuthKey")
		if list, ok := t["preAuthKeys"].([]any); ok {
			for _, e := range list {
				if k, ok := e.(map[string]any); ok {
					maskKey(k)
				}
			}
		}
		for _, c := range t {
			dropJoinKeys(c)
		}
	case []any:
		for _, c := range t {
			dropJoinKeys(c)
		}
	}
}

// proxyGet proxies a GET request to Headscale
// userIDOr404 resolves a user name for a handler. A failed lookup may be a transport error naming
// Headscale's internal address, so the detail is logged and the caller only gets a 404.
func userIDOr404(w http.ResponseWriter, name string) (string, bool) {
	id, err := getUserIDByName(name)
	if err != nil {
		log.Printf("headscale: user lookup %q: %v", name, err)
		router.JSONError(w, "user not found", http.StatusNotFound)
		return "", false
	}
	return id, true
}

// headscaleUnreachable answers a failed call to Headscale. The transport error names Headscale's
// internal address, so it goes to the server log only; the caller gets a generic message.
func headscaleUnreachable(w http.ResponseWriter, err error) {
	log.Printf("headscale: request failed: %v", err)
	router.JSONError(w, "Headscale is unreachable", http.StatusFailedDependency)
}

func (s *Service) proxyGet(w http.ResponseWriter, path string) {
	resp, err := helper.HeadscaleGet(path)
	if err != nil {
		headscaleUnreachable(w, err)
		return
	}
	s.proxyResponse(w, resp, path)
}

// proxyPost proxies a POST request to Headscale with optional JSON body
func (s *Service) proxyPost(w http.ResponseWriter, path string, body string) {
	resp, err := helper.HeadscalePost(path, body)
	if err != nil {
		headscaleUnreachable(w, err)
		return
	}
	s.proxyResponse(w, resp, path)
}

// proxyDelete proxies a DELETE request to Headscale
func (s *Service) proxyDelete(w http.ResponseWriter, path string) {
	resp, err := helper.HeadscaleDelete(path)
	if err != nil {
		headscaleUnreachable(w, err)
		return
	}
	s.proxyResponse(w, resp, path)
}

// --- Users ---

func (s *Service) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/user")
}

func (s *Service) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	// Validate the name (same rule as delete) so it can never carry HTML/JS
	// that later gets rendered in the UI. Root-cause fix for stored XSS.
	if !validName.MatchString(req.Name) {
		router.JSONError(w, "invalid user name (allowed: letters, digits, _ and -)", http.StatusBadRequest)
		return
	}
	body, _ := json.Marshal(req)
	s.proxyPost(w, "/user", string(body))
}

// handleDeleteUser deletes a user and, first, every node they own (Headscale keeps a user who still
// has nodes). One step-up covers the whole delete. The user's nodes are picked from the full node
// list by owner here, so a filter Headscale might ignore can never widen the delete.
func (s *Service) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/hs/users/")
	if !validName.MatchString(name) {
		router.JSONError(w, "invalid user name", http.StatusBadRequest)
		return
	}
	// Destructive + irreversible (it takes the user's devices off the VPN): step-up re-auth.
	if !router.StepUp(w, r) {
		return
	}

	userID, ok := userIDOr404(w, name)
	if !ok {
		return
	}
	nodes, err := GetNodes()
	if err != nil {
		headscaleUnreachable(w, err)
		return
	}
	removed := 0
	for _, n := range nodes {
		if n.User.Name != name || !validNodeID.MatchString(n.ID) {
			continue
		}
		forgetNode(n.ID)
		resp, err := helper.HeadscaleDelete("/node/" + n.ID)
		if err != nil {
			headscaleUnreachable(w, err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("headscale: delete node %s of %s: %s", n.ID, name, resp.Status)
			router.JSONError(w, "could not delete the user's devices", http.StatusBadGateway)
			return
		}
		removed++
	}

	actor := ""
	if p := router.CurrentUser(r); p != nil {
		actor = p.Username
	}
	events.Audit("headscale", "user_delete", events.SeverityWarning, actor, helper.GetClientIP(r),
		fmt.Sprintf("User %s deleted with %d device(s)", name, removed))
	s.proxyDelete(w, "/user/"+userID)
}

func (s *Service) handleRenameUser(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hs/users/")
	parts := strings.Split(path, "/rename/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	if !validName.MatchString(parts[0]) || !validName.MatchString(parts[1]) {
		router.JSONError(w, "invalid user name", http.StatusBadRequest)
		return
	}

	// Lookup user ID by name
	userID, ok := userIDOr404(w, parts[0])
	if !ok {
		return
	}

	s.proxyPost(w, "/user/"+userID+"/rename/"+parts[1], "")
}

// --- Nodes ---

func (s *Service) handleGetNodes(w http.ResponseWriter, r *http.Request) {
	path := "/node"
	if user := r.URL.Query().Get("user"); user != "" {
		if !validName.MatchString(user) {
			router.JSONError(w, "invalid user name", http.StatusBadRequest)
			return
		}
		path += "?user=" + user
	}
	s.proxyGet(w, path)
}

func (s *Service) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/nodes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid node id", http.StatusBadRequest)
		return
	}
	// Destructive + irreversible: require step-up re-auth (password, +2FA when enabled).
	if !router.StepUp(w, r) {
		return
	}

	forgetNode(id)
	s.proxyDelete(w, "/node/"+id)
}

// forgetNode removes the panel's own records of a Headscale node about to be deleted: its row in
// the unified client list and that client's domain routes.
func forgetNode(id string) {
	db, err := database.GetDB()
	if err != nil {
		return
	}
	var clientID int
	err = db.QueryRow(`SELECT id FROM vpn_clients WHERE external_id = ? AND type = 'headscale'`, id).Scan(&clientID)
	if err == nil && clientID > 0 {
		domains.DeleteClientRoutes(clientID)
	}
	db.Exec(`DELETE FROM vpn_clients WHERE external_id = ? AND type = 'headscale'`, id)
}

func (s *Service) handleRenameNode(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hs/nodes/")
	parts := strings.Split(path, "/rename/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	if !validNodeID.MatchString(parts[0]) || !validName.MatchString(parts[1]) {
		router.JSONError(w, "invalid node id or name", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/node/"+parts[0]+"/rename/"+parts[1], "")
}

func (s *Service) handleExpireNode(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/nodes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid node id", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/node/"+id+"/expire", "")
}

func (s *Service) handleUpdateNodeTags(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/nodes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid node id", http.StatusBadRequest)
		return
	}

	var req struct {
		Tags []string `json:"tags"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	tags, err := helper.NormalizeTags(req.Tags, "tag:")
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	body, _ := json.Marshal(map[string][]string{"tags": tags})
	path := "/node/" + id + "/tags"
	resp, err := helper.HeadscalePost(path, string(body))
	if err != nil {
		headscaleUnreachable(w, err)
		return
	}
	if resp.StatusCode < 300 {
		actor := ""
		if p := router.CurrentUser(r); p != nil {
			actor = p.Username
		}
		events.Audit("headscale", "node_tags", events.SeverityInfo, actor, helper.GetClientIP(r),
			fmt.Sprintf("Node %s tags set to [%s]", id, strings.Join(tags, ", ")))
	}
	s.proxyResponse(w, resp, path)
}

// --- Routes ---

func (s *Service) handleGetRoutes(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/routes")
}

func (s *Service) handleEnableRoute(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/routes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid route id", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/routes/"+id+"/enable", "")
}

func (s *Service) handleDisableRoute(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/routes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid route id", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/routes/"+id+"/disable", "")
}

func (s *Service) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/routes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid route id", http.StatusBadRequest)
		return
	}
	s.proxyDelete(w, "/routes/"+id)
}

// --- PreAuth Keys ---

func (s *Service) handleCreatePreAuthKey(w http.ResponseWriter, r *http.Request) {
	// Step-up: minting a preauth key hands out a tailnet-join secret.
	if !router.StepUp(w, r) {
		return
	}
	var req struct {
		User       string `json:"user"`
		Reusable   bool   `json:"reusable"`
		Ephemeral  bool   `json:"ephemeral"`
		Expiration string `json:"expiration"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	body, _ := json.Marshal(req)
	resp, err := helper.HeadscalePost("/preauthkey", string(body))
	if err != nil {
		headscaleUnreachable(w, err)
		return
	}
	// The only reply that carries a whole key: the admin copies it now; the list shows its prefix.
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, maxHeadscaleReply))
}

var validKeyID = regexp.MustCompile(`^[0-9]{1,20}$`)

// handleExpirePreAuthKey expires a key by its id (the browser never holds the whole key): the full
// key, which Headscale 0.25 expires by, is looked up here.
func (s *Service) handleExpirePreAuthKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User string `json:"user"`
		ID   string `json:"id"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if !validName.MatchString(req.User) || !validKeyID.MatchString(req.ID) {
		router.JSONError(w, "invalid user or key id", http.StatusBadRequest)
		return
	}
	key, err := preAuthKeyByID(req.User, req.ID)
	if err != nil {
		headscaleUnreachable(w, err)
		return
	}
	if key == "" {
		router.JSONError(w, "key not found", http.StatusNotFound)
		return
	}
	body, _ := json.Marshal(map[string]string{"user": req.User, "key": key})
	s.proxyPost(w, "/preauthkey/expire", string(body))
}

// preAuthKeyByID returns a user's pre-auth key with id ("" if there's none).
func preAuthKeyByID(user, id string) (string, error) {
	resp, err := helper.HeadscaleGet("/preauthkey?user=" + user)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("headscale answered %s", resp.Status)
	}
	var list struct {
		PreAuthKeys []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"preAuthKeys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxHeadscaleReply)).Decode(&list); err != nil {
		return "", err
	}
	for _, k := range list.PreAuthKeys {
		if k.ID == id {
			return k.Key, nil
		}
	}
	return "", nil
}

// --- API Keys ---

func (s *Service) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	// Step-up: minting an API key issues a headscale control-plane credential.
	if !router.StepUp(w, r) {
		return
	}
	var req struct {
		Expiration string `json:"expiration"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	body, _ := json.Marshal(req)
	s.proxyPost(w, "/apikey", string(body))
}

func (s *Service) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/apikeys/")
	body, _ := json.Marshal(map[string]string{"prefix": id})
	s.proxyPost(w, "/apikey/expire", string(body))
}
