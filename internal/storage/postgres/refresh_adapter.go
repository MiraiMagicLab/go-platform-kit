package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/repositories/postgres"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/domain"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
)

var _ ports.RefreshTokenRepository = (*RefreshTokenAdapter)(nil)

// RefreshTokenAdapter wraps *postgres.RefreshTokenRepo to implement ports.RefreshTokenRepository.
type RefreshTokenAdapter struct {
	repo *postgres.RefreshTokenRepo
}

func NewRefreshTokenAdapter(repo *postgres.RefreshTokenRepo) *RefreshTokenAdapter {
	return &RefreshTokenAdapter{repo: repo}
}

func (a *RefreshTokenAdapter) Create(ctx context.Context, userID, sessionID uuid.UUID, tokenHash string, expiresAt time.Time, ip, ua, deviceName string) (uuid.UUID, error) {
	return a.repo.Create(ctx, userID, sessionID, tokenHash, expiresAt, ip, ua, deviceName)
}

func (a *RefreshTokenAdapter) GetByHash(ctx context.Context, tokenHash string) (domain.RefreshToken, error) {
	dto, err := a.repo.GetByHash(ctx, tokenHash)
	if err != nil {
		return domain.RefreshToken{}, err
	}
	return dtoToRefreshToken(dto), nil
}

func (a *RefreshTokenAdapter) Revoke(ctx context.Context, refreshTokenID uuid.UUID, replacedBy *uuid.UUID) error {
	return a.repo.Revoke(ctx, refreshTokenID, replacedBy)
}

func (a *RefreshTokenAdapter) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	return a.repo.RevokeAllForUser(ctx, userID)
}

func (a *RefreshTokenAdapter) RevokeAllForSession(ctx context.Context, userID, sessionID uuid.UUID) (int64, error) {
	return a.repo.RevokeAllForSession(ctx, userID, sessionID)
}

func (a *RefreshTokenAdapter) RevokeAllExceptSession(ctx context.Context, userID, keepSessionID uuid.UUID) (int64, error) {
	return a.repo.RevokeAllExceptSession(ctx, userID, keepSessionID)
}

func (a *RefreshTokenAdapter) Rotate(ctx context.Context, oldHash, newHash string, newExpires time.Time, ip, ua, deviceName string) (domain.RotateResult, error) {
	res, err := a.repo.Rotate(ctx, oldHash, newHash, newExpires, ip, ua, deviceName)
	if err != nil {
		return domain.RotateResult{}, err
	}
	return domain.RotateResult{
		UserID:            res.UserID,
		SessionID:         res.SessionID,
		NewRefreshTokenID: res.NewRefreshTokenID,
		Invalid:           res.Invalid,
		ReplayDetected:    res.ReplayDetected,
	}, nil
}

func (a *RefreshTokenAdapter) Cleanup(ctx context.Context, now time.Time) error {
	return a.repo.Cleanup(ctx, now)
}

func (a *RefreshTokenAdapter) ListActiveSessions(ctx context.Context, userID uuid.UUID) ([]domain.SessionListInfo, error) {
	rows, err := a.repo.ListActiveSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.SessionListInfo, len(rows))
	for i, r := range rows {
		out[i] = domain.SessionListInfo{
			SessionID:  r.SessionID,
			RefreshID:  r.RefreshID,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: r.LastUsedAt,
			IPAddress:  r.IPAddress,
			UserAgent:  r.UserAgent,
			ExpiresAt:  r.ExpiresAt,
			DeviceName: r.DeviceName,
		}
	}
	return out, nil
}

func dtoToRefreshToken(dto postgres.RefreshTokenDTO) domain.RefreshToken {
	return domain.RefreshToken{
		ID:            dto.ID,
		UserID:        dto.UserID,
		SessionID:     dto.SessionID,
		TokenHash:     dto.TokenHash,
		ExpiresAt:     dto.ExpiresAt,
		RevokedAt:     dto.RevokedAt,
		RevokedReason: dto.RevokedReason,
		CreatedAt:     dto.CreatedAt,
		IPAddress:     dto.IPAddress,
		UserAgent:     dto.UserAgent,
		DeviceName:    dto.DeviceName,
		LastUsedAt:    dto.LastUsedAt,
	}
}
