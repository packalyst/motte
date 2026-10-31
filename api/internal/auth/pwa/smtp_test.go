package pwa

import (
	"bufio"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// TestSTARTTLSNeverFallsBackToPlaintext: with STARTTLS chosen, a mail server that doesn't offer it
// gets no message (before, the alert went out unencrypted).
func TestSTARTTLSNeverFallsBackToPlaintext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var gotMail atomic.Bool
	go func() { // a server without STARTTLS that accepts anything
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("220 synthetic ESMTP\r\n"))
		sc := bufio.NewScanner(conn)
		for sc.Scan() {
			line := strings.ToUpper(sc.Text())
			switch {
			case strings.HasPrefix(line, "EHLO"):
				conn.Write([]byte("250-synthetic\r\n250 8BITMIME\r\n"))
			case strings.HasPrefix(line, "MAIL"):
				gotMail.Store(true)
				conn.Write([]byte("250 OK\r\n"))
			case strings.HasPrefix(line, "QUIT"):
				conn.Write([]byte("221 bye\r\n"))
				return
			default:
				conn.Write([]byte("250 OK\r\n"))
			}
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if err := SaveSMTP(SMTPConfig{Host: "127.0.0.1", Port: port, From: "panel@example.test", TLS: "starttls"}); err != nil {
		t.Fatal(err)
	}

	if err := sendEmail("admin@example.test", "synthetic", "synthetic"); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("send: got %v, want a STARTTLS refusal", err)
	}
	if gotMail.Load() {
		t.Error("the message started going out without encryption")
	}
}
