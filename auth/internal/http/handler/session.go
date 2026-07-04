package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/http/middleware"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/audit"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/usecase/session"
	apperrors "github.com/MiraiMagicLab/go-platform-kit/platform/errors"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// SessionHandler handles session management endpoints.
type SessionHandler struct {
	sessionSvc *session.SessionService
	auditSvc   *audit.AuditService
}

// NewSessionHandler creates a SessionHandler for managing user sessions.
func NewSessionHandler(sessionSvc *session.SessionService, auditSvc *audit.AuditService) *SessionHandler {
	return &SessionHandler{sessionSvc: sessionSvc, auditSvc: auditSvc}
}

// List handles GET /sessions. It returns all active sessions for the authenticated user,
// marking the current session.
func (h *SessionHandler) List(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		httpx.FailCode(c, http.StatusUnauthorized, apperrors.CodeUnauthorized, nil)
		return
	}
	sessions, err := h.sessionSvc.List(c.Request.Context(), userID)
	if err != nil {
		httpx.FailCode(c, http.StatusInternalServerError, apperrors.CodeInternal, nil)
		return
	}
	currentSessionID := middleware.SessionIDFromCtx(c)
	type sessionView struct {
		ID         string  `json:"id"`
		DeviceName *string `json:"device_name,omitempty"`
		IPAddress  *string `json:"ip_address,omitempty"`
		UserAgent  *string `json:"user_agent,omitempty"`
		Current    bool    `json:"current"`
		CreatedAt  string  `json:"created_at"`
		LastSeenAt string  `json:"last_seen_at"`
	}
	out := make([]sessionView, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionView{
			ID:         s.ID.String(),
			DeviceName: s.DeviceName,
			IPAddress:  s.IPAddress,
			UserAgent:  s.UserAgent,
			Current:    s.ID == currentSessionID,
			CreatedAt:  s.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			LastSeenAt: s.LastSeenAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	httpx.Success(c, http.StatusOK, "success", out, nil)
}

// RevokeOne handles DELETE /sessions/:id. It revokes a specific session by ID,
// adding its access token to the denylist.
func (h *SessionHandler) RevokeOne(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		httpx.FailCode(c, http.StatusUnauthorized, apperrors.CodeUnauthorized, nil)
		return
	}
	targetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		httpx.FailCode(c, http.StatusBadRequest, apperrors.CodeBadRequest, nil)
		return
	}
	currentSessionID := middleware.SessionIDFromCtx(c)
	jti, exp, _ := middleware.AccessTokenMetaFromCtx(c)
	if err := h.sessionSvc.RevokeSession(c.Request.Context(), userID, targetID, currentSessionID, jti, exp); err != nil {
		if err == session.ErrSessionNotFound {
			httpx.FailCode(c, http.StatusNotFound, apperrors.CodeNotFound, nil)
			return
		}
		httpx.FailCode(c, http.StatusInternalServerError, apperrors.CodeInternal, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "session.revoke", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"target": targetID.String()})
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

// RevokeOthers handles DELETE /sessions/others. It revokes all sessions
// except the current one for the authenticated user.
func (h *SessionHandler) RevokeOthers(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		httpx.FailCode(c, http.StatusUnauthorized, apperrors.CodeUnauthorized, nil)
		return
	}
	keepSessionID := middleware.SessionIDFromCtx(c)
	if err := h.sessionSvc.RevokeOtherSessions(c.Request.Context(), userID, keepSessionID); err != nil {
		httpx.FailCode(c, http.StatusInternalServerError, apperrors.CodeInternal, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "session.revoke_others", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}
