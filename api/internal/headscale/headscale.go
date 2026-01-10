package headscale

import (
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
	body := fmt.Sprintf(`{"name": "%s"}`, name)
	resp, err := helper.HeadscalePost("/user", body)
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

// CreatePreAuthKey creates a pre-auth key for a user
func CreatePreAuthKey(user string, reusable, ephemeral bool, expiration time.Time) (string, error) {
	body := fmt.Sprintf(`{"user": "%s", "reusable": %t, "ephemeral": %t, "expiration": "%s"}`,
		user, reusable, ephemeral, expiration.Format(time.RFC3339))

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
	log.Printf("Headscale service initialized (reads config from database)")
	return &Service{}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetUsers":          s.handleGetUsers,
		"CreateUser":        s.handleCreateUser,
		"DeleteUser":        s.handleDeleteUser,
		"RenameUser":        s.handleRenameUser,
		"GetNodes":          s.handleGetNodes,
		"DeleteNode":        s.handleDeleteNode,
		"RenameNode":        s.handleRenameNode,
		"ExpireNode":        s.handleExpireNode,
		"GetNodeRoutes":     s.handleGetNodeRoutes,
		"UpdateNodeTags":    s.handleUpdateNodeTags,
		"GetRoutes":         s.handleGetRoutes,
		"EnableRoute":       s.handleEnableRoute,
		"DisableRoute":      s.handleDisableRoute,
		"DeleteRoute":       s.handleDeleteRoute,
		"GetPreAuthKeys":    s.handleGetPreAuthKeys,
		"CreatePreAuthKey":  s.handleCreatePreAuthKey,
		"ExpirePreAuthKey":  s.handleExpirePreAuthKey,
		"GetAPIKeys":        s.handleGetAPIKeys,
		"CreateAPIKey":      s.handleCreateAPIKey,
		"DeleteAPIKey":      s.handleDeleteAPIKey,
	}
}

// --- HTTP helpers ---

// proxyResponse writes the Headscale response to the client
func (s *Service) proxyResponse(w http.ResponseWriter, resp *http.Response) {
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyGet proxies a GET request to Headscale
func (s *Service) proxyGet(w http.ResponseWriter, path string) {
	resp, err := helper.HeadscaleGet(path)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.proxyResponse(w, resp)
}

// proxyPost proxies a POST request to Headscale with optional JSON body
func (s *Service) proxyPost(w http.ResponseWriter, path string, body string) {
	resp, err := helper.HeadscalePost(path, body)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.proxyResponse(w, resp)
}

// proxyDelete proxies a DELETE request to Headscale
func (s *Service) proxyDelete(w http.ResponseWriter, path string) {
	resp, err := helper.HeadscaleDelete(path)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.proxyResponse(w, resp)
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
	body, _ := json.Marshal(req)
	s.proxyPost(w, "/user", string(body))
}

func (s *Service) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/hs/users/")
	if !validName.MatchString(name) {
		router.JSONError(w, "invalid user name", http.StatusBadRequest)
		return
	}

	userID, err := getUserIDByName(name)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusNotFound)
		return
	}

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
	userID, err := getUserIDByName(parts[0])
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusNotFound)
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

	// Auto-delete from vpn_clients for unified view
	if db, err := database.GetDB(); err == nil {
		// Get client ID and delete associated domain routes first
		var clientID int
		err := db.QueryRow(`SELECT id FROM vpn_clients WHERE external_id = ? AND type = 'headscale'`, id).Scan(&clientID)
		if err == nil && clientID > 0 {
			domains.DeleteClientRoutes(clientID)
		}
		db.Exec(`DELETE FROM vpn_clients WHERE external_id = ? AND type = 'headscale'`, id)
	}

	s.proxyDelete(w, "/node/"+id)
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

func (s *Service) handleGetNodeRoutes(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/nodes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid node id", http.StatusBadRequest)
		return
	}
	s.proxyGet(w, "/node/"+id+"/routes")
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

	body, _ := json.Marshal(map[string][]string{"tags": req.Tags})
	s.proxyPost(w, "/node/"+id+"/tags", string(body))
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

func (s *Service) handleGetPreAuthKeys(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		router.JSONError(w, "user parameter required", http.StatusBadRequest)
		return
	}
	if !validName.MatchString(user) {
		router.JSONError(w, "invalid user name", http.StatusBadRequest)
		return
	}
	s.proxyGet(w, "/preauthkey?user="+user)
}

func (s *Service) handleCreatePreAuthKey(w http.ResponseWriter, r *http.Request) {
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
	s.proxyPost(w, "/preauthkey", string(body))
}

func (s *Service) handleExpirePreAuthKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User string `json:"user"`
		Key  string `json:"key"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	body, _ := json.Marshal(req)
	s.proxyPost(w, "/preauthkey/expire", string(body))
}

// --- API Keys ---

func (s *Service) handleGetAPIKeys(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/apikey")
}

func (s *Service) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
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

