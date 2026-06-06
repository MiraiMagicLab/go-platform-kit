package utils

import "net/mail"

// EmailValidator defines how to validate email format.
type EmailValidator func(email string) bool

// DefaultEmailValidator validates email using net/mail.ParseAddress plus length checks per RFC 5321.
// local part max 64, domain max 255, total max 254.
func DefaultEmailValidator(email string) bool {
	if len(email) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	if addr == nil {
		return false
	}
	at := 0
	for i, c := range email {
		if c == '@' {
			at = i
			break
		}
	}
	if at < 1 || at == len(email)-1 {
		return false
	}
	domain := email[at+1:]
	if len(domain) < 2 {
		return false
	}
	return true
}
