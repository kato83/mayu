// Package notification provides email notification and preset templates
// for vulnerability alerting (Slack, Teams, Email).
package notification

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
)

// EmailSender sends notification emails via SMTP.
type EmailSender struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      bool
}

// Send delivers an HTML email to the given recipients.
// It uses STARTTLS when TLS is true and the server supports it,
// or falls back to plain SMTP on port 25.
func (s *EmailSender) Send(ctx context.Context, to []string, subject, htmlBody string) error {
	if len(to) == 0 {
		return fmt.Errorf("notification: no recipients specified")
	}
	if s.Host == "" {
		return fmt.Errorf("notification: SMTP host is not configured")
	}

	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))

	// Build the email message with MIME headers.
	msg := buildMIMEMessage(s.From, to, subject, htmlBody)

	// Connect to the SMTP server.
	conn, err := net.DialTimeout("tcp", addr, smtpDialTimeout)
	if err != nil {
		return fmt.Errorf("notification: dial SMTP %s: %w", addr, err)
	}

	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("notification: SMTP client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Upgrade to TLS if configured.
	if s.TLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				ServerName: s.Host,
				MinVersion: tls.VersionTLS12,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("notification: STARTTLS: %w", err)
			}
		}
	}

	// Authenticate if credentials are provided.
	if s.Username != "" && s.Password != "" {
		auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("notification: SMTP auth: %w", err)
		}
	}

	// Set envelope sender.
	if err := client.Mail(s.From); err != nil {
		return fmt.Errorf("notification: MAIL FROM: %w", err)
	}

	// Set recipients.
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("notification: RCPT TO %s: %w", rcpt, err)
		}
	}

	// Write message body.
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("notification: DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("notification: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notification: close data: %w", err)
	}

	return client.Quit()
}

// buildMIMEMessage constructs a complete MIME email message with HTML content type.
func buildMIMEMessage(from string, to []string, subject, htmlBody string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	b.WriteString("\r\n")
	b.WriteString(htmlBody)
	return []byte(b.String())
}
