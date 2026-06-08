package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/internal/mocks"
	"github.com/MiraiMagicLab/go-platform-kit/internal/session"
	"github.com/MiraiMagicLab/go-platform-kit/pkg/domain"
)

func TestSessionService_List(t *testing.T) {
	userID := uuid.New()
	sessions := &mocks.SessionRepoMock{
		ListActiveFunc: func(ctx context.Context, uid uuid.UUID) ([]domain.Session, error) {
			assert.Equal(t, userID, uid)
			return []domain.Session{
				{ID: uuid.New(), UserID: userID},
				{ID: uuid.New(), UserID: userID},
			}, nil
		},
	}

	svc := session.NewSessionService(sessions, nil, nil)
	result, err := svc.List(context.Background(), userID)

	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestSessionService_CreateSession(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()

	sessions := &mocks.SessionRepoMock{
		CreateFunc: func(ctx context.Context, uid uuid.UUID, deviceName, ip, ua string) (uuid.UUID, error) {
			assert.Equal(t, userID, uid)
			assert.Equal(t, "Test Device", deviceName)
			assert.Equal(t, "127.0.0.1", ip)
			assert.Equal(t, "test-agent", ua)
			return sessionID, nil
		},
	}

	svc := session.NewSessionService(sessions, nil, nil)
	id, err := svc.CreateSession(context.Background(), userID, "Test Device", "127.0.0.1", "test-agent")

	require.NoError(t, err)
	assert.Equal(t, sessionID, id)
}

func TestSessionService_RevokeSession_Success(t *testing.T) {
	userID := uuid.New()
	targetID := uuid.New()

	sessions := &mocks.SessionRepoMock{
		RevokeFunc: func(ctx context.Context, id uuid.UUID) (int64, error) {
			assert.Equal(t, targetID, id)
			return 1, nil
		},
	}
	refresh := &mocks.RefreshTokenRepoMock{
		RevokeAllForSessionFunc: func(ctx context.Context, uid, sid uuid.UUID) (int64, error) {
			assert.Equal(t, userID, uid)
			assert.Equal(t, targetID, sid)
			return 0, nil
		},
	}

	svc := session.NewSessionService(sessions, refresh, nil)
	err := svc.RevokeSession(context.Background(), userID, targetID, uuid.Nil, "", time.Time{})

	require.NoError(t, err)
}

func TestSessionService_RevokeSession_NotFound(t *testing.T) {
	userID := uuid.New()
	targetID := uuid.New()

	sessions := &mocks.SessionRepoMock{
		RevokeFunc: func(ctx context.Context, id uuid.UUID) (int64, error) {
			return 0, nil // no rows affected
		},
	}

	svc := session.NewSessionService(sessions, nil, nil)
	err := svc.RevokeSession(context.Background(), userID, targetID, uuid.Nil, "", time.Time{})

	assert.ErrorIs(t, err, session.ErrSessionNotFound)
}

func TestSessionService_RevokeSession_DenylistsAccessToken(t *testing.T) {
	userID := uuid.New()
	targetID := uuid.New()
	jti := uuid.New().String()
	accessExp := time.Now().Add(15 * time.Minute)

	sessions := &mocks.SessionRepoMock{
		RevokeFunc: func(ctx context.Context, id uuid.UUID) (int64, error) {
			return 1, nil
		},
	}
	refresh := &mocks.RefreshTokenRepoMock{}
	denylist := mocks.NewDenylistMock()

	svc := session.NewSessionService(sessions, refresh, denylist)
	err := svc.RevokeSession(context.Background(), userID, targetID, targetID, jti, accessExp)

	require.NoError(t, err)
	assert.True(t, denylist.IsDeniedJTI(jti))
}

func TestSessionService_RevokeOtherSessions(t *testing.T) {
	userID := uuid.New()
	keepID := uuid.New()

	sessions := &mocks.SessionRepoMock{
		RevokeAllExceptFunc: func(ctx context.Context, uid, keepID uuid.UUID) (int64, error) {
			assert.Equal(t, userID, uid)
			assert.Equal(t, keepID, keepID)
			return 2, nil
		},
	}
	refresh := &mocks.RefreshTokenRepoMock{
		RevokeAllExceptSessionFunc: func(ctx context.Context, uid, keepID uuid.UUID) (int64, error) {
			return 2, nil
		},
	}

	svc := session.NewSessionService(sessions, refresh, nil)
	err := svc.RevokeOtherSessions(context.Background(), userID, keepID)

	require.NoError(t, err)
}

func TestSessionService_RevokeOtherSessions_NilKeepID(t *testing.T) {
	svc := session.NewSessionService(nil, nil, nil)
	err := svc.RevokeOtherSessions(context.Background(), uuid.New(), uuid.Nil)

	assert.Error(t, err)
}

func TestSessionService_RevokeAllSessions(t *testing.T) {
	userID := uuid.New()

	sessions := &mocks.SessionRepoMock{
		RevokeAllForUserFunc: func(ctx context.Context, uid uuid.UUID) error {
			assert.Equal(t, userID, uid)
			return nil
		},
	}
	refresh := &mocks.RefreshTokenRepoMock{
		RevokeAllForUserFunc: func(ctx context.Context, uid uuid.UUID) error {
			assert.Equal(t, userID, uid)
			return nil
		},
	}

	svc := session.NewSessionService(sessions, refresh, nil)
	err := svc.RevokeAllSessions(context.Background(), userID)

	require.NoError(t, err)
}
