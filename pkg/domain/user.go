package domain

import (
	"time"

	"github.com/google/uuid"
)

// User is the aggregate root for authentication and authorization.
type User struct {
	ID                   uuid.UUID  `json:"id"`
	Email                string     `json:"email"`
	PasswordHash         string     `json:"-"`
	EmailVerified        bool       `json:"email_verified"`
	PasswordLoginEnabled bool       `json:"password_login_enabled"`
	BannedUntil          *time.Time `json:"banned_until,omitempty"`
	BanReason            *string    `json:"ban_reason,omitempty"`
	TokenVersion         int        `json:"-"`
	FailedLoginCount     int        `json:"-"`
	LockedUntil          *time.Time `json:"locked_until,omitempty"`
	DeletedAt            *time.Time `json:"deleted_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// IsBanned returns true if the user is currently banned.
func (u *User) IsBanned() bool {
	return u.BannedUntil != nil && time.Now().Before(*u.BannedUntil)
}

// IsLocked returns true if the account is temporarily locked due to failed login attempts.
func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && time.Now().Before(*u.LockedUntil)
}

// IsDeleted returns true if the user has been soft-deleted.
func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil
}

// CanLogin checks all preconditions for login: not banned, not locked, not deleted, password login enabled.
func (u *User) CanLogin(requireEmailVerified bool) error {
	if !u.PasswordLoginEnabled {
		return ErrInvalidCredentials
	}
	if u.IsBanned() {
		return ErrUserBanned{Until: u.BannedUntil, Reason: u.BanReason}
	}
	if u.IsLocked() {
		return ErrAccountLocked{Until: u.LockedUntil}
	}
	if u.IsDeleted() {
		return ErrInvalidCredentials
	}
	if requireEmailVerified && !u.EmailVerified {
		return ErrEmailNotVerified{}
	}
	return nil
}

// IsPasswordLoginEnabled returns true if the user can log in with email/password.
func (u *User) IsPasswordLoginEnabled() bool {
	return u.PasswordLoginEnabled
}
