package server

import (
	"testing"
	"time"
)

// Timestamp prefixes seen in the wild across distros/loggers. The parser must read
// all of these — the content after the timestamp is identical everywhere.
var timestampPrefixes = map[string]string{
	"ubuntu24-rsyslog-iso":   "2026-08-16T18:36:42.387291+03:00",
	"journald-short-iso":     "2026-08-16T18:36:42+0200",
	"iso-utc-z":              "2026-08-16T18:36:42.123456Z",
	"iso-no-frac":            "2026-08-16T18:36:42+00:00",
	"debian-traditional":     "Aug 16 18:36:42",
	"debian-traditional-pad": "Aug  6 08:06:02", // single-digit day is space-padded
}

func lineWith(prefix, msg string) string { return prefix + " host " + msg }

func TestTimestampFormatsGeneral(t *testing.T) {
	now := time.Now()
	for name, prefix := range timestampPrefixes {
		line := lineWith(prefix, "sshd[1234]: Accepted publickey for alice from 1.2.3.4 port 55234 ssh2")
		if _, ok := parseAnyTime(line, now); !ok {
			t.Errorf("[%s] timestamp %q not parsed", name, prefix)
		}
		if reAccepted.FindStringSubmatch(line) == nil {
			t.Errorf("[%s] login content not matched", name)
		}
	}
}

// The content regexes must match regardless of process name (sshd vs sshd-session),
// pid brackets, and spacing — none of which are distro-stable.
func TestContentFormatsGeneral(t *testing.T) {
	cases := []struct {
		name, line string
		re         interface{ FindStringSubmatch(string) []string }
		want       bool
	}{
		{"login-sshd", "T host sshd[1]: Accepted password for alice from 9.9.9.9 port 1 ssh2", reAccepted, true},
		{"login-sshd-session", "T host sshd-session[1]: Accepted publickey for alice from 9.9.9.9 port 1 ssh2", reAccepted, true},
		{"failed-invaliduser", "T host sshd[1]: Failed password for invalid user admin from 5.6.7.8 port 2 ssh2", reFailed, true},
		{"failed-plain", "T host sshd-session[1]: Failed password for root from 5.6.7.8 port 2 ssh2", reFailed, true},
		{"sudo-cmd", "T host sudo:    alice : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt update", reSudoCmd, true},
		{"sudo-cmd-pid", "T host sudo[9]: alice : COMMAND=/bin/ls", reSudoCmd, true},
		{"newuser", "T host useradd[9]: new user: name=bob, UID=1001", reNewUser, true},
	}
	for _, c := range cases {
		got := c.re.FindStringSubmatch(c.line) != nil
		if got != c.want {
			t.Errorf("[%s] match=%v want=%v", c.name, got, c.want)
		}
	}
	// sudo failure ("incorrect password attempts", plural) must count.
	if !reSudoFail.MatchString("T host sudo:    alice : 3 incorrect password attempts ; TTY=pts/0") {
		t.Error("sudo failure line not matched")
	}
}
