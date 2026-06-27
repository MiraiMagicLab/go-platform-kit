package mail

import (
	"context"
	"fmt"
	netsmtp "net/smtp"
)

var _ Mailer = (*SMTPSender)(nil)

// SMTPSender delivers email via SMTP AUTH.
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
func (s *SMTPSender) Send(_ context.Context, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", s.from, to, subject, body)
	auth := netsmtp.PlainAuth("", s.user, s.pass, s.host)
	return netsmtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg))
}
