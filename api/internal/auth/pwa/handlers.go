package pwa

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api/internal/auth"
	"api/internal/helper"
	"api/internal/router"
	"api/internal/ws"
)

const timeFormat = "2006-01-02T15:04:05Z"

// safeSubscription is the public-safe representation of a subscription (no keys exposed)
type safeSubscription struct {
	ID         int64  `json:"id"`
	DeviceName string `json:"deviceName"`
	Endpoint   string `json:"endpoint"`
	UserAgent  string `json:"userAgent,omitempty"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
	LoadError  string `json:"loadError,omitempty"`
}

// toSafeSubscriptions converts internal subscriptions to safe public format
func toSafeSubscriptions(subs []PushSubscription) []safeSubscription {
	result := make([]safeSubscription, len(subs))
	for i, sub := range subs {
		result[i] = safeSubscription{
			ID:         sub.ID,
			DeviceName: sub.DeviceName,
			Endpoint:   sub.Endpoint,
			UserAgent:  sub.UserAgent,
			CreatedAt:  sub.CreatedAt.Format(timeFormat),
			LoadError:  sub.LoadError,
		}
		if sub.LastUsedAt != nil {
			result[i].LastUsedAt = sub.LastUsedAt.Format(timeFormat)
		}
	}
	return result
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetVAPIDKey":      s.handleGetVAPIDKey,
		"GetSubscriptions": s.handleGetSubscriptions,
		"Subscribe":        s.handleSubscribe,
		"Unsubscribe":      s.handleUnsubscribe,
		"Preferences":      s.handlePreferences,
		"Locations":        s.handleLocations,
		"StoreLocation":    s.handleStoreLocation,
		"TestNotification": s.handleTestNotification,
	}
}

// getUserID extracts and validates the user from the request token
func getUserID(r *http.Request) (int64, error) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		return 0, auth.ErrInvalidSession
	}

	authSvc := auth.GetService()
	if authSvc == nil {
		return 0, auth.ErrInvalidSession
	}

	user, err := authSvc.ValidateSession(token)
	if err != nil {
		return 0, err
	}

	return user.ID, nil
}

// broadcastSubscriptionsUpdate broadcasts updated subscriptions list to all user's connected clients
func (s *Service) broadcastSubscriptionsUpdate(userID int64) {
	subs, err := s.GetUserSubscriptions(userID)
	if err != nil {
		return
	}
	ws.BroadcastToUser(userID, "pwa_subscriptions", toSafeSubscriptions(subs))
}

// handleGetVAPIDKey returns the public VAPID key for client subscription
func (s *Service) handleGetVAPIDKey(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{
		"publicKey": s.GetVAPIDPublicKey(),
	})
}

// handleGetSubscriptions handles GET (list) and DELETE (revoke) for push subscriptions
func (s *Service) handleGetSubscriptions(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		subs, err := s.GetUserSubscriptions(userID)
		if err != nil {
			router.JSONError(w, "Failed to get subscriptions", http.StatusInternalServerError)
			return
		}
		router.JSON(w, toSafeSubscriptions(subs))

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			router.JSONError(w, "Subscription ID required", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			router.JSONError(w, "Invalid subscription ID", http.StatusBadRequest)
			return
		}

		if err := s.DeleteSubscription(id, userID); err != nil {
			router.JSONError(w, "Failed to delete subscription", http.StatusInternalServerError)
			return
		}

		// Broadcast updated subscriptions to all user's clients
		go s.broadcastSubscriptionsUpdate(userID)

		router.JSON(w, map[string]bool{"success": true})

	default:
		router.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSubscribe creates a new push subscription
func (s *Service) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req SubscribeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sub, err := s.Subscribe(userID, &req, r.UserAgent())
	if err != nil {
		if err == ErrInvalidSubscription {
			router.JSONError(w, "Invalid subscription data", http.StatusBadRequest)
			return
		}
		router.JSONError(w, "Failed to subscribe", http.StatusInternalServerError)
		return
	}

	// Broadcast updated subscriptions to all user's clients
	go s.broadcastSubscriptionsUpdate(userID)

	router.JSON(w, map[string]interface{}{
		"id":         sub.ID,
		"deviceName": sub.DeviceName,
	})
}

// handleUnsubscribe removes a push subscription
func (s *Service) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Endpoint string `json:"endpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.Unsubscribe(userID, req.Endpoint); err != nil {
		if err == ErrSubscriptionNotFound {
			router.JSONError(w, "Subscription not found", http.StatusNotFound)
			return
		}
		router.JSONError(w, "Failed to unsubscribe", http.StatusInternalServerError)
		return
	}

	// Broadcast updated subscriptions to all user's clients
	go s.broadcastSubscriptionsUpdate(userID)

	router.JSON(w, map[string]bool{"success": true})
}

// handlePreferences handles GET and PUT for notification preferences
func (s *Service) handlePreferences(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		prefs, err := s.GetPreferences(userID)
		if err != nil {
			router.JSONError(w, "Failed to get preferences", http.StatusInternalServerError)
			return
		}
		router.JSON(w, prefs)

	case http.MethodPut:
		var prefs NotificationPreferences
		if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
			router.JSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if err := s.UpdatePreferences(userID, prefs); err != nil {
			router.JSONError(w, "Failed to update preferences", http.StatusInternalServerError)
			return
		}

		router.JSON(w, prefs)

	default:
		router.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLocations handles GET and DELETE for device locations
func (s *Service) handleLocations(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Parse query params
		limitStr := r.URL.Query().Get("limit")
		limit := MaxLocationResults
		if limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil {
				limit = l
			}
		}

		// Check if requesting latest per device
		if strings.ToLower(r.URL.Query().Get("latest")) == "true" {
			locs, err := s.GetLatestLocationPerDevice(userID)
			if err != nil {
				router.JSONError(w, "Failed to get locations", http.StatusInternalServerError)
				return
			}
			router.JSON(w, locs)
			return
		}

		locs, err := s.GetUserLocations(userID, limit)
		if err != nil {
			router.JSONError(w, "Failed to get locations", http.StatusInternalServerError)
			return
		}

		router.JSON(w, locs)

	case http.MethodDelete:
		// Check for specific ID
		idStr := r.URL.Query().Get("id")
		if idStr != "" {
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				router.JSONError(w, "Invalid ID", http.StatusBadRequest)
				return
			}

			if err := s.DeleteLocation(userID, id); err != nil {
				router.JSONError(w, "Location not found", http.StatusNotFound)
				return
			}

			router.JSON(w, map[string]bool{"success": true})
			return
		}

		// Delete all locations for user
		if strings.ToLower(r.URL.Query().Get("all")) == "true" {
			if err := s.DeleteAllLocations(userID); err != nil {
				router.JSONError(w, "Failed to delete locations", http.StatusInternalServerError)
				return
			}

			router.JSON(w, map[string]bool{"success": true})
			return
		}

		router.JSONError(w, "Specify 'id' or 'all=true'", http.StatusBadRequest)

	default:
		router.JSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleStoreLocation saves a new device location (POST only)
func (s *Service) handleStoreLocation(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req LocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Basic validation
	if req.Latitude < -90 || req.Latitude > 90 || req.Longitude < -180 || req.Longitude > 180 {
		router.JSONError(w, "Invalid coordinates", http.StatusBadRequest)
		return
	}

	loc, err := s.StoreLocation(userID, &req)
	if err != nil {
		router.JSONError(w, "Failed to store location", http.StatusInternalServerError)
		return
	}

	router.JSON(w, loc)
}

// handleTestNotification sends a test push notification to the user
func (s *Service) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		router.JSONError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Use unique tag with timestamp so each test notification is shown separately
	tag := "test-" + strconv.FormatInt(time.Now().UnixNano(), 36)

	err = s.SendNotificationToUser(userID, &Notification{
		Title: "Test Notification",
		Body:  "Push notifications are working correctly!",
		Icon:  DefaultNotificationIcon,
		Tag:   tag,
		Data: map[string]string{
			"type": "test",
			"url":  "/profile",
		},
	})

	if err != nil {
		router.JSONError(w, "Failed to send notification", http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]bool{"success": true})
}
