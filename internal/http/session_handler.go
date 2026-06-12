package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/audit"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/http/middleware"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/session"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/response"
)

// SessionHandler handles session management endpoints.
type SessionHandler struct {
	sessionSvc *session.SessionService
	auditSvc   *audit.AuditService
}

func NewSessionHandler(sessionSvc *session.SessionService, auditSvc *audit.AuditService) *SessionHandler {
	return &SessionHandler{sessionSvc: sessionSvc, auditSvc: auditSvc}
}

func (h *SessionHandler) List(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	sessions, err := h.sessionSvc.List(c.Request.Context(), userID)
	if err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
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
	response.Success(c, http.StatusOK, "success", out, nil)
}

func (h *SessionHandler) RevokeOne(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	targetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	currentSessionID := middleware.SessionIDFromCtx(c)
	jti, exp, _ := middleware.AccessTokenMetaFromCtx(c)
	if err := h.sessionSvc.RevokeSession(c.Request.Context(), userID, targetID, currentSessionID, jti, exp); err != nil {
		if err == session.ErrSessionNotFound {
			response.FailCode(c, http.StatusNotFound, response.CodeCommonNotFound, nil)
			return
		}
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "session.revoke", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{"target": targetID.String()})
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

func (h *SessionHandler) RevokeOthers(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	keepSessionID := middleware.SessionIDFromCtx(c)
	if err := h.sessionSvc.RevokeOtherSessions(c.Request.Context(), userID, keepSessionID); err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "session.revoke_others", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}
