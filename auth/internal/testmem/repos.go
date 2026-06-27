// Package testmem provides in-memory repository doubles for auth unit tests.
package testmem

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
)

type Users struct {
	mu    sync.Mutex
	byID  map[uuid.UUID]domain.User
	byEmail map[string]uuid.UUID
}

func NewUsers() *Users {
	return &Users{
		byID:    make(map[uuid.UUID]domain.User),
		byEmail: make(map[string]uuid.UUID),
	}
}

func (m *Users) Create(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	return m.create(email, passwordHash, true)
}

func (m *Users) CreateOAuthUser(ctx context.Context, email, passwordHash string) (uuid.UUID, error) {
	return m.create(email, passwordHash, false)
}

func (m *Users) create(email, passwordHash string, passwordLogin bool) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.New()
	now := time.Now()
	u := domain.User{
		ID:                   id,
		Email:                email,
		PasswordHash:         passwordHash,
		PasswordLoginEnabled: passwordLogin,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	m.byID[id] = u
	m.byEmail[email] = id
	return id, nil
}

func (m *Users) GetByEmail(ctx context.Context, email string) (domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byEmail[email]
	if !ok {
		return domain.User{}, domain.ErrInvalidCredentials
	}
	return m.byID[id], nil
}

func (m *Users) GetByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return domain.User{}, domain.ErrInvalidCredentials
	}
	return u, nil
}

func (m *Users) IncrementTokenVersion(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.byID[userID]
	u.TokenVersion++
	m.byID[userID] = u
	return nil
}

func (m *Users) SetPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.byID[userID]
	u.PasswordHash = passwordHash
	m.byID[userID] = u
	return nil
}

func (m *Users) SetEmailVerified(ctx context.Context, userID uuid.UUID, verified bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.byID[userID]
	u.EmailVerified = verified
	m.byID[userID] = u
	return nil
}

func (m *Users) SetBan(ctx context.Context, userID uuid.UUID, bannedUntil *time.Time, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.byID[userID]
	u.BannedUntil = bannedUntil
	if reason != "" {
		u.BanReason = &reason
	}
	m.byID[userID] = u
	return nil
}

func (m *Users) IncrementFailedLogin(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.byID[userID]
	u.FailedLoginCount++
	m.byID[userID] = u
	return nil
}

func (m *Users) ResetFailedLogin(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.byID[userID]
	u.FailedLoginCount = 0
	m.byID[userID] = u
	return nil
}

func (m *Users) SetLock(ctx context.Context, userID uuid.UUID, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.byID[userID]
	u.LockedUntil = &until
	m.byID[userID] = u
	return nil
}

func (m *Users) SoftDelete(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.byID[userID]
	now := time.Now()
	u.DeletedAt = &now
	m.byID[userID] = u
	return nil
}

func (m *Users) ListUsers(ctx context.Context, page, pageSize int, filter ports.ListUsersFilter) ([]domain.User, int, error) {
	return nil, 0, nil
}

func (m *Users) SetUser(id uuid.UUID, u domain.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[id] = u
	m.byEmail[u.Email] = id
}

type Sessions struct {
	mu      sync.Mutex
	created []uuid.UUID
	active  map[uuid.UUID]domain.Session
}

func NewSessions() *Sessions {
	return &Sessions{active: make(map[uuid.UUID]domain.Session)}
}

func (m *Sessions) Create(ctx context.Context, userID uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error) {
	id := uuid.New()
	return id, m.CreateWithID(ctx, id, userID, deviceName, ip, ua, time.Now())
}

func (m *Sessions) CreateWithID(ctx context.Context, id, userID uuid.UUID, deviceName, ip, ua string, createdAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.created = append(m.created, id)
	m.active[id] = domain.Session{ID: id, UserID: userID, CreatedAt: createdAt, LastSeenAt: createdAt}
	return nil
}

func (m *Sessions) ListActive(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []domain.Session
	for _, s := range m.active {
		if s.UserID == userID && !s.IsRevoked() {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *Sessions) Touch(ctx context.Context, sessionID uuid.UUID, ip, ua, deviceName string) error {
	return nil
}

func (m *Sessions) Revoke(ctx context.Context, sessionID uuid.UUID) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.active[sessionID]
	if !ok || s.IsRevoked() {
		return 0, nil
	}
	now := time.Now()
	s.RevokedAt = &now
	m.active[sessionID] = s
	return 1, nil
}

func (m *Sessions) RevokeAllExcept(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, s := range m.active {
		if s.UserID == userID && id != keepSessionID && !s.IsRevoked() {
			now := time.Now()
			s.RevokedAt = &now
			m.active[id] = s
			n++
		}
	}
	return n, nil
}

func (m *Sessions) GetByID(ctx context.Context, sessionID uuid.UUID) (domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[sessionID], nil
}

func (m *Sessions) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for id, s := range m.active {
		if s.UserID == userID && !s.IsRevoked() {
			s.RevokedAt = &now
			m.active[id] = s
		}
	}
	return nil
}

func (m *Sessions) Cleanup(ctx context.Context, now time.Time) error { return nil }

func (m *Sessions) Created() []uuid.UUID {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uuid.UUID, len(m.created))
	copy(out, m.created)
	return out
}

type RefreshTokens struct {
	mu     sync.Mutex
	byHash map[string]domain.RefreshToken
	revokedSessions map[uuid.UUID]bool
}

func NewRefreshTokens() *RefreshTokens {
	return &RefreshTokens{
		byHash:          make(map[string]domain.RefreshToken),
		revokedSessions: make(map[uuid.UUID]bool),
	}
}

func (m *RefreshTokens) Create(ctx context.Context, userID, sessionID uuid.UUID, tokenHash string, expiresAt time.Time, ip, ua, deviceName string) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.New()
	m.byHash[tokenHash] = domain.RefreshToken{
		ID:        id,
		UserID:    userID,
		SessionID: sessionID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		LastUsedAt: time.Now(),
	}
	return id, nil
}

func (m *RefreshTokens) GetByHash(ctx context.Context, tokenHash string) (domain.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.byHash[tokenHash]
	if !ok {
		return domain.RefreshToken{}, domain.ErrInvalidRefresh
	}
	return rt, nil
}

func (m *RefreshTokens) Revoke(ctx context.Context, refreshTokenID uuid.UUID, replacedBy *uuid.UUID) error {
	return nil
}

func (m *RefreshTokens) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for hash, rt := range m.byHash {
		if rt.UserID == userID && !rt.IsRevoked() {
			rt.RevokedAt = &now
			m.byHash[hash] = rt
		}
	}
	return nil
}

func (m *RefreshTokens) RevokeAllForSession(ctx context.Context, userID, sessionID uuid.UUID) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokedSessions[sessionID] = true
	now := time.Now()
	var n int64
	for hash, rt := range m.byHash {
		if rt.UserID == userID && rt.SessionID == sessionID && !rt.IsRevoked() {
			rt.RevokedAt = &now
			m.byHash[hash] = rt
			n++
		}
	}
	return n, nil
}

func (m *RefreshTokens) RevokeAllExceptSession(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var n int64
	for hash, rt := range m.byHash {
		if rt.UserID == userID && rt.SessionID != keepSessionID && !rt.IsRevoked() {
			rt.RevokedAt = &now
			m.byHash[hash] = rt
			n++
		}
	}
	return n, nil
}

func (m *RefreshTokens) Rotate(ctx context.Context, oldHash, newHash string, newExpires time.Time, ip, ua, deviceName string) (domain.RotateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.byHash[oldHash]
	if !ok || old.IsRevoked() || old.IsExpired() {
		return domain.RotateResult{Invalid: true}, nil
	}
	now := time.Now()
	old.RevokedAt = &now
	m.byHash[oldHash] = old
	newID := uuid.New()
	m.byHash[newHash] = domain.RefreshToken{
		ID:        newID,
		UserID:    old.UserID,
		SessionID: old.SessionID,
		TokenHash: newHash,
		ExpiresAt: newExpires,
		CreatedAt: now,
		LastUsedAt: now,
	}
	return domain.RotateResult{
		UserID:            old.UserID,
		SessionID:         old.SessionID,
		NewRefreshTokenID: &newID,
	}, nil
}

func (m *RefreshTokens) Cleanup(ctx context.Context, now time.Time) error { return nil }

func (m *RefreshTokens) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]domain.SessionListInfo, error) {
	return nil, nil
}

type MFA struct {
	mu    sync.Mutex
	items map[uuid.UUID]domain.MFAConfig
	codes map[uuid.UUID]map[string]bool
}

func NewMFA() *MFA {
	return &MFA{
		items: make(map[uuid.UUID]domain.MFAConfig),
		codes: make(map[uuid.UUID]map[string]bool),
	}
}

func (m *MFA) UpsertTOTPSecret(ctx context.Context, userID uuid.UUID, secret string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.items[userID]
	cfg.UserID = userID
	cfg.TOTPSecret = secret
	cfg.CreatedAt = time.Now()
	m.items[userID] = cfg
	return nil
}

func (m *MFA) GetMFA(ctx context.Context, userID uuid.UUID) (domain.MFAConfig, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, ok := m.items[userID]
	return cfg, ok && cfg.TOTPSecret != "", nil
}

func (m *MFA) EnableMFA(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg := m.items[userID]
	cfg.Enabled = true
	now := time.Now()
	cfg.EnabledAt = &now
	m.items[userID] = cfg
	return nil
}

func (m *MFA) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, userID)
	delete(m.codes, userID)
	return nil
}

func (m *MFA) ReplaceRecoveryCodes(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[userID] = make(map[string]bool)
	for _, h := range codeHashes {
		m.codes[userID][h] = true
	}
	return nil
}

func (m *MFA) UseRecoveryCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.codes[userID][codeHash] {
		delete(m.codes[userID], codeHash)
		return true, nil
	}
	return false, nil
}

func (m *MFA) Cleanup(ctx context.Context, now time.Time) error { return nil }

type RBAC struct {
	mu          sync.Mutex
	roles       map[string]uuid.UUID
	perms       map[string]uuid.UUID
	rolePerms   map[uuid.UUID][]uuid.UUID
	userRoles   map[uuid.UUID][]uuid.UUID
}

func NewRBAC() *RBAC {
	return &RBAC{
		roles:     make(map[string]uuid.UUID),
		perms:     make(map[string]uuid.UUID),
		rolePerms: make(map[uuid.UUID][]uuid.UUID),
		userRoles: make(map[uuid.UUID][]uuid.UUID),
	}
}

func (m *RBAC) CreateRole(ctx context.Context, name string) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.roles[name]; ok {
		return id, nil
	}
	id := uuid.New()
	m.roles[name] = id
	return id, nil
}

func (m *RBAC) CreatePermission(ctx context.Context, name string) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.perms[name]; ok {
		return id, nil
	}
	id := uuid.New()
	m.perms[name] = id
	return id, nil
}

func (m *RBAC) AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rolePerms[roleID] = append(m.rolePerms[roleID], permissionIDs...)
	return nil
}

func (m *RBAC) AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userRoles[userID] = append(m.userRoles[userID], roleIDs...)
	return nil
}

func (m *RBAC) ListUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	permNames := make(map[string]struct{})
	for _, roleID := range m.userRoles[userID] {
		for _, permID := range m.rolePerms[roleID] {
			for name, id := range m.perms {
				if id == permID {
					permNames[name] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(permNames))
	for name := range permNames {
		out = append(out, name)
	}
	return out, nil
}

func (m *RBAC) ListUserIDsByRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []uuid.UUID
	for uid, roles := range m.userRoles {
		for _, rid := range roles {
			if rid == roleID {
				out = append(out, uid)
				break
			}
		}
	}
	return out, nil
}

func (m *RBAC) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, roleID := range m.userRoles[userID] {
		for name, id := range m.roles {
			if id == roleID {
				out = append(out, name)
			}
		}
	}
	return out, nil
}

func (m *RBAC) GetRoleIDByName(ctx context.Context, name string) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.roles[name]
	if !ok {
		return uuid.Nil, domain.ErrInvalidCredentials
	}
	return id, nil
}

type Identity struct {
	mu   sync.Mutex
	keys map[string]uuid.UUID
}

func NewIdentity() *Identity {
	return &Identity{keys: make(map[string]uuid.UUID)}
}

func (m *Identity) key(provider, subject string) string {
	return provider + ":" + subject
}

func (m *Identity) FindUserIDByProvider(ctx context.Context, provider, providerSubject string) (uuid.UUID, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.keys[m.key(provider, providerSubject)]
	return id, ok, nil
}

func (m *Identity) LinkIdentity(ctx context.Context, userID uuid.UUID, provider, providerSubject, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[m.key(provider, providerSubject)] = userID
	return nil
}

type StringCache struct {
	mu   sync.Mutex
	data map[string][]string
}

func NewStringCache() *StringCache {
	return &StringCache{data: make(map[string][]string)}
}

func (c *StringCache) Get(ctx context.Context, key string) ([]string, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[key]
	return v, ok, nil
}

func (c *StringCache) Set(ctx context.Context, key string, value []string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
	return nil
}

func (c *StringCache) Del(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
	return nil
}

type Denylist struct {
	mu    sync.Mutex
	items map[string]bool
}

func NewDenylist() *Denylist {
	return &Denylist{items: make(map[string]bool)}
}

func (d *Denylist) IsDenied(ctx context.Context, jti string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.items[jti], nil
}

func (d *Denylist) Deny(ctx context.Context, jti string, ttl time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.items[jti] = true
	return nil
}

type EmailTokens struct {
	mu     sync.Mutex
	tokens map[string]emailTokenRow
}

type emailTokenRow struct {
	userID     uuid.UUID
	actionType string
	tokenHash  string
	expiresAt  time.Time
	used       bool
}

func NewEmailTokens() *EmailTokens {
	return &EmailTokens{tokens: make(map[string]emailTokenRow)}
}

func (m *EmailTokens) key(actionType, tokenHash string) string {
	return actionType + ":" + tokenHash
}

func (m *EmailTokens) Create(ctx context.Context, userID uuid.UUID, actionType, tokenHash string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[m.key(actionType, tokenHash)] = emailTokenRow{
		userID: userID, actionType: actionType, tokenHash: tokenHash, expiresAt: expiresAt,
	}
	return nil
}

func (m *EmailTokens) Consume(ctx context.Context, actionType, tokenHash string, now time.Time) (uuid.UUID, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.tokens[m.key(actionType, tokenHash)]
	if !ok || row.used || now.After(row.expiresAt) {
		return uuid.Nil, false, nil
	}
	row.used = true
	m.tokens[m.key(actionType, tokenHash)] = row
	return row.userID, true, nil
}

func (m *EmailTokens) Cleanup(ctx context.Context, now time.Time) error { return nil }

// StoreRawTokenForTest records a raw token hash mapping for tests that know the hash only.
func (m *EmailTokens) StoreRawTokenForTest(userID uuid.UUID, actionType, tokenHash string, expiresAt time.Time) {
	_ = m.Create(context.Background(), userID, actionType, tokenHash, expiresAt)
}
