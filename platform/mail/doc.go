// Package mail provides a shared email delivery abstraction for platform capabilities
// and host applications.
//
// Auth uses it for verify/reset emails; future notify, billing, and admin modules
// can share the same [Mailer] without importing auth.
//
// Open an SMTP sender from infra config:
//
//	mailer, err := mail.Open(mail.Config{
//	    Host: cfg.Infra.Mail.Host,
//	    Port: cfg.Infra.Mail.Port,
//	    User: cfg.Infra.Mail.User,
//	    Pass: cfg.Infra.Mail.Pass,
//	    From: cfg.Infra.Mail.From,
//	})
package mail
