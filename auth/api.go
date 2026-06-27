package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	login "github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/login"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/oauth"
)

// LoginResult is returned by login, refresh, and MFA completion flows.
type LoginResult = login.LoginResult

func (a *Auth) require() error {
	if a == nil || a.loginSvc == nil {
		return errors.New("auth: not initialized")
	}
	return nil
}

// Register creates a user account and assigns the default role when configured.
func (a *Auth) Register(ctx context.Context, email, password string) (uuid.UUID, error) {
	if err := a.require(); err != nil {
		return uuid.Nil, err
	}
	id, err := a.loginSvc.Register(ctx, email, password)
	if err != nil {
		return uuid.Nil, err
	}
	if a.cfg.DefaultRegisterRole != "" && a.rbacSvc != nil {
		if assignErr := a.rbacSvc.AssignRoleByName(ctx, id, a.cfg.DefaultRegisterRole); assignErr != nil {
			return id, assignErr
		}
	}
	return id, nil
}

// Login authenticates credentials and returns tokens or an MFA challenge.
func (a *Auth) Login(ctx context.Context, email, password string, meta ClientMeta) (LoginResult, error) {
	if err := a.require(); err != nil {
		return LoginResult{}, err
	}
	return a.loginSvc.Login(ctx, email, password, meta)
}

// CompleteMFA completes login after TOTP or recovery code verification.
func (a *Auth) CompleteMFA(ctx context.Context, mfaToken, otpOrRecovery string, meta ClientMeta) (LoginResult, error) {
	if err := a.require(); err != nil {
		return LoginResult{}, err
	}
	return a.loginSvc.CompleteMFA(ctx, mfaToken, otpOrRecovery, meta)
}

// Refresh rotates refresh token and issues new tokens.
func (a *Auth) Refresh(ctx context.Context, refreshToken string, meta ClientMeta, deviceName string) (LoginResult, error) {
	if err := a.require(); err != nil {
		return LoginResult{}, err
	}
	return a.loginSvc.Refresh(ctx, refreshToken, meta, deviceName)
}

// Logout invalidates the current session tokens for a user.
func (a *Auth) Logout(ctx context.Context, userID, sessionID uuid.UUID, accessJTI string, accessExpiresAt time.Time) error {
	if err := a.require(); err != nil {
		return err
	}
	return a.loginSvc.Logout(ctx, userID, sessionID, accessJTI, accessExpiresAt)
}

// StartSession issues tokens for an already-authenticated user (e.g. after OAuth or register).
func (a *Auth) StartSession(ctx context.Context, userID uuid.UUID, meta ClientMeta, deviceName string) (LoginResult, error) {
	if err := a.require(); err != nil {
		return LoginResult{}, err
	}
	return a.loginSvc.StartSession(ctx, userID, meta, deviceName)
}

// GetProfile returns the user profile with roles and permissions.
func (a *Auth) GetProfile(ctx context.Context, userID uuid.UUID) (UserProfile, error) {
	if a == nil || a.users == nil {
		return UserProfile{}, errors.New("auth: not initialized")
	}
	u, err := a.users.GetByID(ctx, userID)
	if err != nil {
		return UserProfile{}, err
	}
	roles, _ := a.ListUserRoles(ctx, userID)
	perms, _ := a.ListUserPermissions(ctx, userID)
	return UserProfile{User: u, Roles: roles, Permissions: perms}, nil
}

// IsMFAEnabled reports whether MFA is active for the user.
func (a *Auth) IsMFAEnabled(ctx context.Context, userID uuid.UUID) (bool, error) {
	if a == nil || a.mfaSvc == nil {
		return false, errors.New("auth: mfa service not initialized")
	}
	return a.mfaSvc.IsEnabled(ctx, userID)
}

// RequestVerifyEmail sends a verification email.
func (a *Auth) RequestVerifyEmail(ctx context.Context, userID uuid.UUID) error {
	if a == nil || a.emailSvc == nil {
		return errors.New("auth: email service not configured")
	}
	return a.emailSvc.RequestVerifyEmail(ctx, userID)
}

// ConfirmVerifyEmail marks email verified from a raw token.
func (a *Auth) ConfirmVerifyEmail(ctx context.Context, rawToken string) error {
	if a == nil || a.emailSvc == nil {
		return errors.New("auth: email service not configured")
	}
	return a.emailSvc.ConfirmVerifyEmail(ctx, rawToken)
}

// ForgotPassword starts password reset flow.
func (a *Auth) ForgotPassword(ctx context.Context, email string) error {
	if a == nil || a.emailSvc == nil {
		return errors.New("auth: email service not configured")
	}
	return a.emailSvc.ForgotPassword(ctx, email)
}

// ResetPassword completes password reset from raw token.
func (a *Auth) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	if a == nil || a.emailSvc == nil {
		return errors.New("auth: email service not configured")
	}
	return a.emailSvc.ResetPassword(ctx, rawToken, newPassword)
}

// ListSessions lists active sessions for a user.
func (a *Auth) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	if a == nil || a.sessionSvc == nil {
		return nil, errors.New("auth: session service not initialized")
	}
	return a.sessionSvc.List(ctx, userID)
}

// RevokeSession revokes one session.
func (a *Auth) RevokeSession(ctx context.Context, userID, targetSessionID, currentSessionID uuid.UUID, accessJTI string, accessExp time.Time) error {
	if a == nil || a.sessionSvc == nil {
		return errors.New("auth: session service not initialized")
	}
	return a.sessionSvc.RevokeSession(ctx, userID, targetSessionID, currentSessionID, accessJTI, accessExp)
}

// RevokeOtherSessions revokes all sessions except the given one.
func (a *Auth) RevokeOtherSessions(ctx context.Context, userID, keepSessionID uuid.UUID) error {
	if a == nil || a.sessionSvc == nil {
		return errors.New("auth: session service not initialized")
	}
	return a.sessionSvc.RevokeOtherSessions(ctx, userID, keepSessionID)
}

// SetupMFA starts TOTP setup for a user.
func (a *Auth) SetupMFA(ctx context.Context, userID uuid.UUID, accountName string) (MFASetup, error) {
	if a == nil || a.mfaSvc == nil {
		return MFASetup{}, errors.New("auth: mfa service not initialized")
	}
	return a.mfaSvc.SetupTOTP(ctx, userID, accountName)
}

// EnableMFA enables TOTP after setup verification.
func (a *Auth) EnableMFA(ctx context.Context, userID uuid.UUID, otpCode string) error {
	if a == nil || a.mfaSvc == nil {
		return errors.New("auth: mfa service not initialized")
	}
	return a.mfaSvc.EnableTOTP(ctx, userID, otpCode)
}

// DisableMFA disables MFA for a user.
func (a *Auth) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	if a == nil || a.mfaSvc == nil {
		return errors.New("auth: mfa service not initialized")
	}
	return a.mfaSvc.Disable(ctx, userID)
}

// ListUserRoles returns role names for a user.
func (a *Auth) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if a == nil || a.rbacSvc == nil {
		return nil, errors.New("auth: rbac service not initialized")
	}
	return a.rbacSvc.ListUserRoles(ctx, userID)
}

// ListUserPermissions returns permission names for a user.
func (a *Auth) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if a == nil || a.rbacSvc == nil {
		return nil, errors.New("auth: rbac service not initialized")
	}
	return a.rbacSvc.ListUserPermissions(ctx, userID)
}

// CreateRole creates an RBAC role.
func (a *Auth) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	if a == nil || a.rbacSvc == nil {
		return uuid.Nil, errors.New("auth: rbac service not initialized")
	}
	return a.rbacSvc.CreateRole(ctx, name)
}

// CreatePermission creates an RBAC permission.
func (a *Auth) CreatePermission(ctx context.Context, name string) (uuid.UUID, error) {
	if a == nil || a.rbacSvc == nil {
		return uuid.Nil, errors.New("auth: rbac service not initialized")
	}
	return a.rbacSvc.CreatePermission(ctx, name)
}

// AssignPermissionsToRole assigns permissions to a role.
func (a *Auth) AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if a == nil || a.rbacSvc == nil {
		return errors.New("auth: rbac service not initialized")
	}
	return a.rbacSvc.AssignPermissionsToRole(ctx, roleID, permissionIDs)
}

// AssignRolesToUser assigns roles to a user.
func (a *Auth) AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	if a == nil || a.rbacSvc == nil {
		return errors.New("auth: rbac service not initialized")
	}
	return a.rbacSvc.AssignRolesToUser(ctx, userID, roleIDs)
}

// BanUser bans a user until the given time.
func (a *Auth) BanUser(ctx context.Context, userID uuid.UUID, until time.Time, reason string) error {
	if a == nil || a.adminSvc == nil {
		return errors.New("auth: admin service not initialized")
	}
	return a.adminSvc.BanUser(ctx, userID, until, reason)
}

// UnbanUser removes a ban from a user.
func (a *Auth) UnbanUser(ctx context.Context, userID uuid.UUID) error {
	if a == nil || a.adminSvc == nil {
		return errors.New("auth: admin service not initialized")
	}
	return a.adminSvc.UnbanUser(ctx, userID)
}

// DeleteUser soft-deletes a user and revokes tokens.
func (a *Auth) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	if a == nil || a.adminSvc == nil {
		return errors.New("auth: admin service not initialized")
	}
	return a.adminSvc.DeleteUser(ctx, userID)
}

// ListUsers lists users with pagination and filters.
func (a *Auth) ListUsers(ctx context.Context, page, pageSize int, filter ListUsersFilter) ([]User, int, error) {
	if a == nil || a.adminSvc == nil {
		return nil, 0, errors.New("auth: admin service not initialized")
	}
	return a.adminSvc.ListUsers(ctx, page, pageSize, filter)
}

// OAuthAuthCodeURL returns the provider consent URL.
func (a *Auth) OAuthAuthCodeURL(provider OAuthProvider, state string) (string, error) {
	if a == nil || a.oauthSvc == nil {
		return "", errors.New("auth: oauth service not initialized")
	}
	return a.oauthSvc.AuthCodeURL(oauth.Provider(provider), state)
}

// OAuthExchange exchanges a Google authorization code and issues session tokens.
func (a *Auth) OAuthExchange(ctx context.Context, provider OAuthProvider, code string, meta ClientMeta) (LoginResult, error) {
	if a == nil || a.oauthSvc == nil || a.loginSvc == nil {
		return LoginResult{}, errors.New("auth: oauth service not initialized")
	}
	if provider != OAuthGoogle {
		return LoginResult{}, oauth.ErrUnsupportedProvider
	}
	identity, err := a.oauthSvc.ExchangeAndFetchIdentity(ctx, oauth.Provider(provider), code)
	if err != nil {
		return LoginResult{}, oauth.MapExchangeError(err)
	}
	userID, created, err := a.oauthSvc.FindOrCreateUserForIdentity(ctx, identity)
	if err != nil {
		return LoginResult{}, oauth.MapExchangeError(err)
	}
	if created && a.cfg.DefaultRegisterRole != "" && a.rbacSvc != nil {
		if assignErr := a.rbacSvc.AssignRoleByName(ctx, userID, a.cfg.DefaultRegisterRole); assignErr != nil {
			return LoginResult{}, assignErr
		}
	}
	return a.loginSvc.StartSession(ctx, userID, meta, "")
}

// GoogleOAuthConfigured reports whether Google OAuth is configured on this instance.
func (a *Auth) GoogleOAuthConfigured() bool {
	return a != nil && a.oauthSvc != nil && a.oauthSvc.GoogleConfigured()
}
