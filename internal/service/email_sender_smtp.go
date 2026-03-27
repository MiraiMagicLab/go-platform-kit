package service

import (
	"context"
	"fmt"
	"net/smtp"
)

type SMTPSender struct {
	host string
	port int
	user string
	pass string
	from string
}

func NewSMTPSender(host string, port int, user, pass, from string) *SMTPSender {
	return &SMTPSender{host: host, port: port, user: user, pass: pass, from: from}
}

func (s *SMTPSender) Send(_ context.Context, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	auth := smtp.PlainAuth("", s.user, s.pass, s.host)
	msg := []byte(
		"From: " + s.from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
			body + "\r\n",
	)
	return smtp.SendMail(addr, auth, s.from, []string{to}, msg)
}
