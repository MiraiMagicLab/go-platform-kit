package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/internal/repositories/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/ports"
)

var _ ports.SessionRepository = (*SessionAdapter)(nil)

// SessionAdapter wraps *postgres.SessionsRepo to implement ports.SessionRepository.
type SessionAdapter struct {
	repo *postgres.SessionsRepo
}

func NewSessionAdapter(repo *postgres.SessionsRepo) *SessionAdapter {
	return &SessionAdapter{repo: repo}
}

func (a *SessionAdapter) Create(ctx context.Context, userID uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error) {
	return a.repo.Create(ctx, userID, deviceName, ip, ua)
}

func (a *SessionAdapter) CreateWithID(ctx context.Context, id, userID uuid.UUID, deviceName, ip, ua string, createdAt time.Time) error {
	return a.repo.CreateWithID(ctx, id, userID, deviceName, ip, ua, createdAt)
}

func (a *SessionAdapter) ListActive(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	rows, err := a.repo.ListActive(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Session, len(rows))
	for i, r := range rows {
		out[i] = dtoToSession(r)
	}
	return out, nil
}

func (a *SessionAdapter) Touch(ctx context.Context, sessionID uuid.UUID, ip, ua, deviceName string) error {
	return a.repo.Touch(ctx, sessionID, ip, ua, deviceName)
}

func (a *SessionAdapter) Revoke(ctx context.Context, sessionID uuid.UUID) (int64, error) {
	return a.repo.Revoke(ctx, sessionID)
}

func (a *SessionAdapter) RevokeAllExcept(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error) {
	return a.repo.RevokeAllExcept(ctx, userID, keepSessionID)
}

func (a *SessionAdapter) GetByID(ctx context.Context, sessionID uuid.UUID) (domain.Session, error) {
	row, err := a.repo.GetByID(ctx, sessionID)
	if err != nil {
		return domain.Session{}, err
	}
	return dtoToSession(row), nil
}

func (a *SessionAdapter) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	return a.repo.RevokeAllForUser(ctx, userID)
}

func (a *SessionAdapter) Cleanup(ctx context.Context, now time.Time) error {
	return a.repo.Cleanup(ctx, now)
}

func dtoToSession(row postgres.SessionRow) domain.Session {
	return domain.Session{
		ID:         row.ID,
		UserID:     row.UserID,
		DeviceName: row.DeviceName,
		IPAddress:  row.IPAddress,
		UserAgent:  row.UserAgent,
		CreatedAt:  row.CreatedAt,
		LastSeenAt: row.LastSeenAt,
		RevokedAt:  row.RevokedAt,
	}
}
