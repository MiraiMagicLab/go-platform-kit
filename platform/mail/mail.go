package mail

import (
	"context"
	"errors"
	"strings"
)

// ErrNotConfigured indicates mail was requested without required settings.
var ErrNotConfigured = errors.New("mail: not configured")

// Mailer delivers plain-text email messages.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// Config holds SMTP connection settings shared across capabilities.
type Config struct {
	Host string
	Port int
	User string
	Pass string
	From string
}

// IsConfigured reports whether enough SMTP settings exist to send mail.
func (c Config) IsConfigured() bool {
	return c.Host != "" && c.User != "" && c.Pass != "" && c.From != ""
}

// Validate checks SMTP settings.
func (c Config) Validate() error {
	if !c.IsConfigured() {
		return ErrNotConfigured
	}
	if c.Port <= 0 {
		return errors.New("mail: Port must be > 0")
	}
	if !strings.Contains(c.From, "@") {
		return errors.New("mail: From must be a valid email address")
	}
	return nil
}

// Open returns an SMTP [Mailer] when cfg is configured.
func Open(cfg Config) (Mailer, error) {
	if !cfg.IsConfigured() {
		return nil, ErrNotConfigured
	}
	if cfg.Port <= 0 {
		cfg.Port = 587
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return NewSMTP(cfg), nil
}
