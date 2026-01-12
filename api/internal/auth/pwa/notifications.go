package pwa

import (
	"encoding/json"
	"sync"
)

// MaxPushWorkers limits concurrent push notification sends
const MaxPushWorkers = 10

// SendNotification sends a push notification to all subscriptions of a notification type
// Runs concurrently with a worker pool for efficiency
func (s *Service) SendNotification(notifType NotificationType, notif *Notification) error {
	subs, err := s.GetAllSubscriptionsForNotificationType(notifType)
	if err != nil {
		return err
	}

	if len(subs) == 0 {
		return nil
	}

	payload, err := json.Marshal(notif)
	if err != nil {
		return err
	}

	// Send concurrently with worker pool (max 10 concurrent)
	s.sendToSubscriptions(subs, payload)
	return nil
}

// SendNotificationToUser sends a push notification to all devices of a specific user
func (s *Service) SendNotificationToUser(userID int64, notif *Notification) error {
	subs, err := s.GetUserSubscriptions(userID)
	if err != nil {
		return err
	}

	if len(subs) == 0 {
		return nil
	}

	payload, err := json.Marshal(notif)
	if err != nil {
		return err
	}

	s.sendToSubscriptions(subs, payload)
	return nil
}

// SendNotificationToUsers sends a push notification to multiple users
func (s *Service) SendNotificationToUsers(userIDs []int64, notif *Notification) error {
	subs, err := s.GetSubscriptionsByUserIDs(userIDs)
	if err != nil {
		return err
	}

	if len(subs) == 0 {
		return nil
	}

	payload, err := json.Marshal(notif)
	if err != nil {
		return err
	}

	s.sendToSubscriptions(subs, payload)
	return nil
}

// sendToSubscriptions sends payload to multiple subscriptions concurrently
func (s *Service) sendToSubscriptions(subs []PushSubscription, payload []byte) {
	// Use buffered channel as semaphore
	sem := make(chan struct{}, MaxPushWorkers)
	var wg sync.WaitGroup

	for i := range subs {
		sub := subs[i] // capture for goroutine
		wg.Add(1)

		go func() {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			s.sendPush(&sub, payload)
		}()
	}

	wg.Wait()
}

// NotifyNodeOffline sends notification when a VPN node goes offline
func (s *Service) NotifyNodeOffline(nodeName string) {
	s.SendNotification(NotifyNodeOffline, &Notification{
		Title: "Node Offline",
		Body:  nodeName + " is no longer connected",
		Icon:  DefaultNotificationIcon,
		Tag:   "node-" + nodeName,
		Data: map[string]string{
			"type": "node_offline",
			"node": nodeName,
			"url":  "/nodes",
		},
	})
}

// NotifyNodeOnline sends notification when a VPN node comes online
func (s *Service) NotifyNodeOnline(nodeName string) {
	s.SendNotification(NotifyNodeOnline, &Notification{
		Title: "Node Online",
		Body:  nodeName + " is now connected",
		Icon:  DefaultNotificationIcon,
		Tag:   "node-" + nodeName,
		Data: map[string]string{
			"type": "node_online",
			"node": nodeName,
			"url":  "/nodes",
		},
	})
}

// NotifyFirewallAlert sends notification for firewall events
func (s *Service) NotifyFirewallAlert(ip, reason string) {
	s.SendNotification(NotifyFirewallAlert, &Notification{
		Title: "Firewall Alert",
		Body:  "IP " + ip + " blocked: " + reason,
		Icon:  DefaultNotificationIcon,
		Tag:   "firewall-" + ip,
		Data: map[string]string{
			"type":   "firewall_alert",
			"ip":     ip,
			"reason": reason,
			"url":    "/firewall",
		},
	})
}

// NotifyNewLogin sends notification when user logs in from new device
// Sends to all OTHER devices (excludes the device that just logged in)
func (s *Service) NotifyNewLogin(userID int64, ip, device, currentUserAgent string) {
	subs, err := s.GetUserSubscriptionsExcluding(userID, currentUserAgent)
	if err != nil || len(subs) == 0 {
		return
	}

	notif := &Notification{
		Title: "New Login",
		Body:  "Login from " + device + " (" + ip + ")",
		Icon:  DefaultNotificationIcon,
		Tag:   "login-" + ip,
		Data: map[string]string{
			"type":   "login_new_device",
			"ip":     ip,
			"device": device,
			"url":    "/profile",
		},
	}

	payload, err := json.Marshal(notif)
	if err != nil {
		return
	}

	s.sendToSubscriptions(subs, payload)
}

// NotifySystemAlert sends a system-wide notification to all users
func (s *Service) NotifySystemAlert(title, message string) {
	s.SendNotification(NotifySystemAlert, &Notification{
		Title: title,
		Body:  message,
		Icon:  DefaultNotificationIcon,
		Tag:   "system",
		Data: map[string]string{
			"type": "system_alert",
		},
	})
}
