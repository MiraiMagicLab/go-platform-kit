package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/MiraiMagicLab/go-auth-lib/internal/middleware"
	"github.com/MiraiMagicLab/go-auth-lib/internal/services"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
)

type SessionHandler struct {
	sessions *services.SessionService
	audit    *services.AuditService
}

func NewSessionHandler(sessions *services.SessionService, audit *services.AuditService) *SessionHandler {
	return &SessionHandler{sessions: sessions, audit: audit}
}

func (h *SessionHandler) List(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	curSID := middleware.SessionIDFromCtx(c)

	rows, err := h.sessions.List(c.Request.Context(), userID)
	if err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		return
	}

	var list []gin.H
	for _, r := range rows {
		list = append(list, gin.H{
			"id":           r.SessionID.String(),
			"created_at":   r.CreatedAt,
			"last_used_at": r.LastUsedAt,
			"ip_address":   r.IPAddress,
			"user_agent":   r.UserAgent,
			"expires_at":   r.ExpiresAt,
			"current":      curSID != uuid.Nil && r.SessionID == curSID,
		})
	}
	response.Success(c, http.StatusOK, "success", gin.H{"sessions": list}, nil)
}

func (h *SessionHandler) RevokeOne(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	sid, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	jti, exp, ok := middleware.AccessTokenMetaFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	curSID := middleware.SessionIDFromCtx(c)

	if err := h.sessions.RevokeSession(c.Request.Context(), userID, sid, curSID, jti, exp); err != nil {
		if err == services.ErrSessionNotFound {
			response.FailCode(c, http.StatusNotFound, response.CodeSessionNotFound, nil)
			return
		}
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		return
	}

	if h.audit != nil {
		meta := map[string]interface{}{"session_id": sid.String(), "same_device": sid == curSID}
		h.audit.Log(c.Request.Context(), &userID, "auth.session_revoke", "success", c.ClientIP(), c.Request.UserAgent(), meta)
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

func (h *SessionHandler) RevokeOthers(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	keep := middleware.SessionIDFromCtx(c)
	if keep == uuid.Nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeAuthSessionUnsupported, map[string]interface{}{
			"hint": "access token must include sid; sign in again to obtain a session-scoped token",
		})
		return
	}
	if err := h.sessions.RevokeOtherSessions(c.Request.Context(), userID, keep); err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeCommonInternal, nil)
		return
	}
	if h.audit != nil {
		h.audit.Log(c.Request.Context(), &userID, "auth.session_revoke_others", "success", c.ClientIP(), c.Request.UserAgent(), map[string]interface{}{
			"keep_session_id": keep.String(),
		})
	}
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}
