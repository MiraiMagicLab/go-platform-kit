package http

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/audit"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/http/middleware"
	"github.com/MiraiMagicLab/go-platform-kit/v2/internal/mfa"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports"
	"github.com/MiraiMagicLab/go-platform-kit/v2/pkg/response"
)

// MFAHandler handles MFA endpoints.
type MFAHandler struct {
	mfaSvc   *mfa.MFAService
	auditSvc *audit.AuditService
	users    ports.UserRepository
}

func NewMFAHandler(mfaSvc *mfa.MFAService, auditSvc *audit.AuditService, users ports.UserRepository) *MFAHandler {
	return &MFAHandler{mfaSvc: mfaSvc, auditSvc: auditSvc, users: users}
}

func (h *MFAHandler) Setup(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	u, err := h.users.GetByID(c.Request.Context(), userID)
	if err != nil {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	setup, err := h.mfaSvc.SetupTOTP(c.Request.Context(), userID, u.Email)
	if err != nil {
		response.FailCode(c, http.StatusInternalServerError, response.CodeMFASetupFailed, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "mfa.setup", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "success", setup, nil)
}

type enableMFAReq struct {
	Code string `json:"code" binding:"required"`
}

func (h *MFAHandler) Enable(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	var req enableMFAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if err := h.mfaSvc.EnableTOTP(c.Request.Context(), userID, req.Code); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeMFAEnableFailed, nil)
		h.auditSvc.Log(c.Request.Context(), &userID, "mfa.enable", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "mfa.enable", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

type disableMFAReq struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (h *MFAHandler) Disable(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.FailCode(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, nil)
		return
	}
	var req disableMFAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeCommonBadRequest, nil)
		return
	}
	if req.Password == "" && req.Code == "" {
		response.FailCode(c, http.StatusBadRequest, response.CodeMFADisableFailed, nil)
		return
	}
	if err := h.mfaSvc.Disable(c.Request.Context(), userID); err != nil {
		response.FailCode(c, http.StatusBadRequest, response.CodeMFADisableFailed, nil)
		h.auditSvc.Log(c.Request.Context(), &userID, "mfa.disable", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "mfa.disable", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}
