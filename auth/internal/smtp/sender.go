package smtp

import (
	"context"
	"fmt"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
	"net/smtp"
)

var _ store.EmailSender = (*Sender)(nil)

// Sender implements store.EmailSender via SMTP.
type Sender struct {
	host, user, pass, from string
	port                   int
}

func NewSender(host string, port int, user, pass, from string) *Sender {
	return &Sender{host: host, port: port, user: user, pass: pass, from: from}
}

func (s *Sender) Send(_ context.Context, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", s.from, to, subject, body)
	auth := smtp.PlainAuth("", s.user, s.pass, s.host)
	return smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg))
}
