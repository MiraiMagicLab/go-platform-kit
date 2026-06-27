package jwt

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestManager_issueAndParseAccessToken(t *testing.T) {
	m := NewManager("access-secret", "refresh-secret", "test")
	uid := uuid.New()
	sid := uuid.New()

	token, jti, err := m.NewAccessToken(uid, 1, sid, time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, jti)

	claims, err := m.ParseAccess(token)
	require.NoError(t, err)
	parsedUID, err := uuid.Parse(claims.Subject)
	require.NoError(t, err)
	require.Equal(t, uid, parsedUID)
	require.Equal(t, sid.String(), claims.SessionID)
}
