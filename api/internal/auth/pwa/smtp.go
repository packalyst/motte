package pwa

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"api/internal/settings"
)

// SMTP is global (one mail server for the panel); recipients are per-user (Channels.Email). Stored
// in the settings key-value store; the password is encrypted at rest and write-only to the UI.
type SMTPConfig struct {
	Host string `json:"host"`
	Port string `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"` // write-only to the UI
	From string `json:"from"`
	TLS  string `json:"tls"` // "starttls" (587) | "tls" (465, implicit) | "none"
}

func LoadSMTP() SMTPConfig {
	host, _ := settings.GetSetting("smtp_host")
	port, _ := settings.GetSetting("smtp_port")
	user, _ := settings.GetSetting("smtp_user")
	pass, _ := settings.GetSettingEncrypted("smtp_pass")
	from, _ := settings.GetSetting("smtp_from")
	mode, _ := settings.GetSetting("smtp_tls")
	if port == "" {
		port = "587"
	}
	if mode == "" {
		mode = "starttls"
	}
	return SMTPConfig{Host: host, Port: port, User: user, Pass: pass, From: from, TLS: mode}
}

func SaveSMTP(c SMTPConfig) error {
	if err := settings.SetSetting("smtp_host", strings.TrimSpace(c.Host)); err != nil {
		return err
	}
	settings.SetSetting("smtp_port", strings.TrimSpace(c.Port))
	settings.SetSetting("smtp_user", strings.TrimSpace(c.User))
	settings.SetSetting("smtp_from", strings.TrimSpace(c.From))
	settings.SetSetting("smtp_tls", strings.TrimSpace(c.TLS))
	if c.Pass != "" { // write-only: a blank/placeholder password keeps the stored one
		return settings.SetSettingEncrypted("smtp_pass", c.Pass)
	}
	return nil
}

func (c SMTPConfig) configured() bool { return c.Host != "" && c.From != "" }

// sendEmail delivers one plain-text message with bounded timeouts. Supports STARTTLS (587),
// implicit TLS (465) and plaintext ("none").
func sendEmail(to, subject, body string) error {
	c := LoadSMTP()
	if !c.configured() {
		return fmt.Errorf("SMTP is not configured")
	}
	addr := net.JoinHostPort(c.Host, c.Port)

	var conn net.Conn
	var err error
	if c.TLS == "tls" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{ServerName: c.Host})
	} else {
		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return err
	}
	defer client.Close()

	if c.TLS == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: c.Host}); err != nil {
				return err
			}
		}
	}
	if c.User != "" {
		if err := client.Auth(smtp.PlainAuth("", c.User, c.Pass, c.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(c.From); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write([]byte(buildMessage(c.From, to, subject, body))); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func buildMessage(from, to, subject, body string) string {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body + "\r\n")
	return b.String()
}
