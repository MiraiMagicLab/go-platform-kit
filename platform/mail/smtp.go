package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	netsmtp "net/smtp"
	"strings"
	"time"
)

const defaultSendTimeout = 30 * time.Second

var _ Mailer = (*SMTPSender)(nil)

// SMTPSender delivers email via SMTP AUTH with STARTTLS when supported.
type SMTPSender struct {
	host, user, pass, from string
	port                   int
}

// NewSMTP creates an SMTP-backed [Mailer].
func NewSMTP(cfg Config) *SMTPSender {
	port := cfg.Port
	if port <= 0 {
		port = 587
	}
	return &SMTPSender{
		host: cfg.Host,
		port: port,
		user: cfg.User,
		pass: cfg.Pass,
		from: cfg.From,
	}
}

// Send delivers a plain-text email message.
func (s *SMTPSender) Send(ctx context.Context, to, subject, body string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	to = strings.TrimSpace(to)
	if to == "" {
		return fmt.Errorf("mail: recipient is required")
	}

	ctx, cancel := context.WithTimeout(ctx, defaultSendTimeout)
	defer cancel()

	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	dialer := net.Dialer{Timeout: defaultSendTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("mail: dial: %w", err)
	}
	defer conn.Close()

	client, err := netsmtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("mail: smtp client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("mail: starttls: %w", err)
		}
	}

	if s.user != "" {
		auth := netsmtp.PlainAuth("", s.user, s.pass, s.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("mail: auth: %w", err)
		}
	}

	if err := client.Mail(s.from); err != nil {
		return fmt.Errorf("mail: mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("mail: rcpt: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("mail: data: %w", err)
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s", s.from, to, subject, body)
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("mail: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: close data: %w", err)
	}
	return client.Quit()
}
