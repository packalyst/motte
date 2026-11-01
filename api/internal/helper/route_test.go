package helper

import (
	"strings"
	"testing"
)

func TestParseRouteLine(t *testing.T) {
	r := parseRouteLine("default via 198.51.100.254 dev eth0 proto static src 198.51.100.1 metric 100")
	if r.dev != "eth0" || r.via != "198.51.100.254" || r.src != "198.51.100.1" {
		t.Fatalf("got %+v", r)
	}
	if r := parseRouteLine("198.51.100.254 dev eth0 src 198.51.100.1 uid 0"); r.src != "198.51.100.1" {
		t.Fatalf("route get: %+v", r)
	}
}

func TestParseAddrLines(t *testing.T) {
	out := "2: eth0    inet 198.51.100.1/24 brd 198.51.100.255 scope global eth0\\       valid_lft forever\n" +
		"2: eth0    inet 203.0.113.10/32 scope global eth0\\       valid_lft forever\n" +
		"2: eth0    inet6 2001:db8::1/64 scope global\n"
	if got := strings.Join(parseAddrLines(out), ","); got != "198.51.100.1,203.0.113.10" {
		t.Fatalf("got %q", got)
	}
}
