package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/testmem"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/session"
)

func TestListActiveSessions(t *testing.T) {
	userID := uuid.New()
	sessions := testmem.NewSessions()
	refresh := testmem.NewRefreshTokens()
	svc := session.NewSessionService(sessions, refresh, testmem.NewDenylist())

	id1 := uuid.New()
	id2 := uuid.New()
	require.NoError(t, sessions.CreateWithID(context.Background(), id1, userID, "", "", "", time.Now()))
	require.NoError(t, sessions.CreateWithID(context.Background(), id2, userID, "", "", "", time.Now()))

	list, err := svc.List(context.Background(), userID)
	require.NoError(t, err)
	require.Len(t, list, 2)
}

func TestRevokeSessionDenylistsCurrentAccess(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()
	sessions := testmem.NewSessions()
	refresh := testmem.NewRefreshTokens()
	denylist := testmem.NewDenylist()
	svc := session.NewSessionService(sessions, refresh, denylist)

	require.NoError(t, sessions.CreateWithID(context.Background(), sessionID, userID, "", "", "", time.Now()))
	exp := time.Now().Add(time.Minute)

	require.NoError(t, svc.RevokeSession(context.Background(), userID, sessionID, sessionID, "jti-1", exp))

	denied, err := denylist.IsDenied(context.Background(), "jti-1")
	require.NoError(t, err)
	require.True(t, denied)
}

func TestRevokeSessionNotFound(t *testing.T) {
	svc := session.NewSessionService(testmem.NewSessions(), testmem.NewRefreshTokens(), nil)
	err := svc.RevokeSession(context.Background(), uuid.New(), uuid.New(), uuid.Nil, "", time.Time{})
	require.ErrorIs(t, err, session.ErrSessionNotFound)
}

func TestRevokeOtherSessions(t *testing.T) {
	userID := uuid.New()
	keep := uuid.New()
	other := uuid.New()
	sessions := testmem.NewSessions()
	refresh := testmem.NewRefreshTokens()
	svc := session.NewSessionService(sessions, refresh, nil)

	require.NoError(t, sessions.CreateWithID(context.Background(), keep, userID, "", "", "", time.Now()))
	require.NoError(t, sessions.CreateWithID(context.Background(), other, userID, "", "", "", time.Now()))

	require.NoError(t, svc.RevokeOtherSessions(context.Background(), userID, keep))

	list, err := svc.List(context.Background(), userID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, keep, list[0].ID)
}

func TestRevokeAllSessions(t *testing.T) {
	userID := uuid.New()
	sessions := testmem.NewSessions()
	refresh := testmem.NewRefreshTokens()
	svc := session.NewSessionService(sessions, refresh, nil)

	id := uuid.New()
	require.NoError(t, sessions.CreateWithID(context.Background(), id, userID, "", "", "", time.Now()))
	require.NoError(t, svc.RevokeAllSessions(context.Background(), userID))

	list, err := svc.List(context.Background(), userID)
	require.NoError(t, err)
	require.Empty(t, list)
}

func TestRevokeOtherSessionsRequiresKeepID(t *testing.T) {
	svc := session.NewSessionService(testmem.NewSessions(), testmem.NewRefreshTokens(), nil)
	err := svc.RevokeOtherSessions(context.Background(), uuid.New(), uuid.Nil)
	require.Error(t, err)
}
