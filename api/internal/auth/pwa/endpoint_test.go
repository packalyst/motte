package pwa

import "testing"

// A push endpoint must be an https URL whose real host is a known push service.
func TestIsValidPushEndpoint(t *testing.T) {
	for ep, ok := range map[string]bool{
		"https://fcm.googleapis.com/fcm/send/abc":           true,
		"https://web.push.apple.com/QH8":                    true,
		"https://wns2-par02p.notify.windows.com/w/?token=x": true,
		"https://fcm.googleapis.com:x@10.0.0.5:8443/p":      false, // the real host is 10.0.0.5
		"https://user@fcm.googleapis.com/p":                 false,
		"http://fcm.googleapis.com/p":                       false,
		"https://fcm.googleapis.com.evil.example/p":         false,
		"https://notify.windows.com/p":                      false, // the suffix alone isn't a host of it
		"https://evilnotify.windows.com.example/p":          false,
		"https://10.0.0.5/fcm.googleapis.com":               false,
	} {
		if isValidPushEndpoint(ep) != ok {
			t.Errorf("isValidPushEndpoint(%q) = %v, want %v", ep, !ok, ok)
		}
	}
}
