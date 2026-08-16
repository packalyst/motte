package server

import (
	"testing"
	"time"
)

// Real Ubuntu 24.04 auth.log lines (modern rsyslog RFC3339 high-precision format).
var sampleLines = []string{
	`2026-08-16T18:36:42.387291+03:00 ubuntu24 sshd[1234]: Accepted publickey for alice from 1.2.3.4 port 55234 ssh2: ED25519 SHA256:abc`,
	`2026-08-16T18:36:42.387291+03:00 ubuntu24 sshd[1234]: Failed password for invalid user admin from 5.6.7.8 port 111 ssh2`,
	`2026-08-16T18:36:42.387291+03:00 ubuntu24 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update`,
	`2026-08-16T18:36:42.387291+03:00 ubuntu24 sudo:    alice : 3 incorrect password attempts ; TTY=pts/0`,
	// Traditional (older Debian/Ubuntu) format, for the fallback path:
	`Aug 16 18:36:42 host sshd[1234]: Accepted password for alice from 1.2.3.4 port 5 ssh2`,
}

func TestFormatMatch(t *testing.T) {
	now := time.Now()
	for _, l := range sampleLines {
		_, ok := parseAnyTime(l, now)
		if !ok {
			t.Errorf("TIMESTAMP not parsed: %s", l)
		}
	}
	if m := reAccepted.FindStringSubmatch(sampleLines[0]); m == nil {
		t.Error("reAccepted did NOT match the Ubuntu-24 login line")
	} else {
		t.Logf("login: method=%s user=%s ip=%s", m[1], m[2], m[3])
	}
	if reFailed.FindStringSubmatch(sampleLines[1]) == nil {
		t.Error("reFailed did NOT match the Ubuntu-24 failed-password line")
	}
	if m := reSudoCmd.FindStringSubmatch(sampleLines[2]); m == nil {
		t.Error("reSudoCmd did NOT match the Ubuntu-24 sudo COMMAND line")
	} else {
		t.Logf("sudo: user=%s cmd=%s", m[1], m[2])
	}
	if !reSudoFail.MatchString(sampleLines[3]) {
		t.Error("reSudoFail did NOT match the 'incorrect password attempts' line")
	}
}
