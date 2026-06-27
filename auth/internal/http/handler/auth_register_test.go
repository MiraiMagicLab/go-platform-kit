package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/http/handler"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/testmem"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/audit"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/rbac"
)

func TestRegisterAssignsDefaultRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	users := testmem.NewUsers()
	rbacRepo := testmem.NewRBAC()
	_, _ = rbacRepo.CreateRole(t.Context(), "user")
	cache := testmem.NewStringCache()
	rbacSvc := rbac.NewRBACService(rbacRepo, cache, 0)

	loginSvc := testmem.NewLoginService(t, users, testmem.NewSessions(), testmem.NewRefreshTokens(), nil, nil)
	authH := handler.NewAuthHandler(loginSvc, nil, rbacSvc, users, audit.NewAuditService(nil), "user", nil, nil)

	body, _ := json.Marshal(map[string]string{
		"email":    "register-" + uuid.NewString() + "@example.com",
		"password": "password123",
	})
	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.POST("/register", authH.Register)
	c.Request = httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, c.Request)

	require.Equal(t, http.StatusCreated, w.Code)

	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	userID, err := uuid.Parse(resp.Data.ID)
	require.NoError(t, err)

	roles, err := rbacSvc.ListUserRoles(t.Context(), userID)
	require.NoError(t, err)
	require.Contains(t, roles, "user")
}

func TestRegisterRejectsShortPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authH := handler.NewAuthHandler(
		testmem.NewLoginService(t, testmem.NewUsers(), testmem.NewSessions(), testmem.NewRefreshTokens(), nil, nil),
		nil, rbac.NewRBACService(testmem.NewRBAC(), testmem.NewStringCache(), 0),
		testmem.NewUsers(), audit.NewAuditService(nil), "user", nil, nil,
	)

	body, _ := json.Marshal(map[string]string{"email": "a@b.c", "password": "short"})
	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.POST("/register", authH.Register)
	c.Request = httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, c.Request)
	require.Equal(t, http.StatusBadRequest, w.Code)
}
