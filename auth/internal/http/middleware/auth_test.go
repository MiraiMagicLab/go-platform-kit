package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/domain"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/http/middleware"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/ports"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/security/jwt"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/testmem"
)

type stubUserCache struct {
	user domain.User
	hit  bool
	gets int
	sets int
}

func (s *stubUserCache) Get(ctx context.Context, userID uuid.UUID) (domain.User, bool, error) {
	s.gets++
	if s.hit {
		return s.user, true, nil
	}
	return domain.User{}, false, nil
}

func (s *stubUserCache) Set(ctx context.Context, user domain.User) error {
	s.sets++
	s.user = user
	s.hit = true
	return nil
}

func TestJWTAuthRejectsMissingBearer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwtm := jwt.NewManager(testmem.TestAccessSecret, testmem.TestRefreshSecret, "test")
	r := gin.New()
	r.GET("/", middleware.JWTAuth(jwtm, testmem.NewUsers(), ports.NoopAccessTokenDenylist{}, nil), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthAcceptsValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userID := uuid.New()
	sessionID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, Email: "u@example.com", TokenVersion: 1})

	jwtm := jwt.NewManager(testmem.TestAccessSecret, testmem.TestRefreshSecret, "test")
	token, _, err := jwtm.NewAccessToken(userID, 1, sessionID, time.Minute)
	require.NoError(t, err)

	r := gin.New()
	r.GET("/", middleware.JWTAuth(jwtm, users, ports.NoopAccessTokenDenylist{}, nil), func(c *gin.Context) {
		got, ok := middleware.UserIDFromCtx(c)
		require.True(t, ok)
		require.Equal(t, userID, got)
		require.Equal(t, sessionID, middleware.SessionIDFromCtx(c))
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestJWTAuthUsesUserCache(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userID := uuid.New()
	cache := &stubUserCache{hit: true, user: domain.User{ID: userID, TokenVersion: 3}}
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, TokenVersion: 99})

	jwtm := jwt.NewManager(testmem.TestAccessSecret, testmem.TestRefreshSecret, "test")
	token, _, err := jwtm.NewAccessToken(userID, 3, uuid.New(), time.Minute)
	require.NoError(t, err)

	r := gin.New()
	r.GET("/", middleware.JWTAuth(jwtm, users, ports.NoopAccessTokenDenylist{}, cache), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 1, cache.gets)
	require.Equal(t, 0, cache.sets)
}

func TestJWTAuthRejectsRevokedJTI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, TokenVersion: 1})
	denylist := testmem.NewDenylist()

	jwtm := jwt.NewManager(testmem.TestAccessSecret, testmem.TestRefreshSecret, "test")
	token, jti, err := jwtm.NewAccessToken(userID, 1, uuid.New(), time.Minute)
	require.NoError(t, err)
	require.NoError(t, denylist.Deny(context.Background(), jti, time.Minute))

	r := gin.New()
	r.GET("/", middleware.JWTAuth(jwtm, users, denylist, nil), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthRejectsStaleTokenVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userID := uuid.New()
	users := testmem.NewUsers()
	users.SetUser(userID, domain.User{ID: userID, TokenVersion: 2})

	jwtm := jwt.NewManager(testmem.TestAccessSecret, testmem.TestRefreshSecret, "test")
	token, _, err := jwtm.NewAccessToken(userID, 1, uuid.New(), time.Minute)
	require.NoError(t, err)

	r := gin.New()
	r.GET("/", middleware.JWTAuth(jwtm, users, ports.NoopAccessTokenDenylist{}, nil), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserAuthCacheContract(t *testing.T) {
	id := uuid.New()
	cache := &stubUserCache{hit: true, user: domain.User{ID: id, TokenVersion: 2}}
	got, ok, err := cache.Get(context.Background(), id)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 2, got.TokenVersion)
}
