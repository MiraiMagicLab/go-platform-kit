package gin

import (
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/store"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/gin/middleware"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/audit"
	"github.com/MiraiMagicLab/go-platform-kit/auth/internal/service/mfa"
	"github.com/MiraiMagicLab/go-platform-kit/platform/httpx"
)

// MFAHandler handles MFA endpoints.
type MFAHandler struct {
	mfaSvc   *mfa.MFAService
	auditSvc *audit.AuditService
	users    store.UserRepository
}

func NewMFAHandler(mfaSvc *mfa.MFAService, auditSvc *audit.AuditService, users store.UserRepository) *MFAHandler {
	return &MFAHandler{mfaSvc: mfaSvc, auditSvc: auditSvc, users: users}
}

func (h *MFAHandler) Setup(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
		return
	}
	u, err := h.users.GetByID(c.Request.Context(), userID)
	if err != nil {
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
		return
	}
	setup, err := h.mfaSvc.SetupTOTP(c.Request.Context(), userID, u.Email)
	if err != nil {
		httpx.FailCode(c, http.StatusInternalServerError, httpx.CodeMFASetupFailed, nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "mfa.setup", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	httpx.Success(c, http.StatusOK, "success", setup, nil)
}

type enableMFAReq struct {
	Code string `json:"code" binding:"required"`
}

func (h *MFAHandler) Enable(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
		return
	}
	var req enableMFAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	if err := h.mfaSvc.EnableTOTP(c.Request.Context(), userID, req.Code); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeMFAEnableFailed, nil)
		h.auditSvc.Log(c.Request.Context(), &userID, "mfa.enable", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "mfa.enable", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}

type disableMFAReq struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (h *MFAHandler) Disable(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		httpx.FailCode(c, http.StatusUnauthorized, httpx.CodeUnauthorized, nil)
		return
	}
	var req disableMFAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeBadRequest, nil)
		return
	}
	if req.Password == "" && req.Code == "" {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeMFADisableFailed, nil)
		return
	}
	if err := h.mfaSvc.Disable(c.Request.Context(), userID); err != nil {
		httpx.FailCode(c, http.StatusBadRequest, httpx.CodeMFADisableFailed, nil)
		h.auditSvc.Log(c.Request.Context(), &userID, "mfa.disable", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	h.auditSvc.Log(c.Request.Context(), &userID, "mfa.disable", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	httpx.Success(c, http.StatusOK, "success", gin.H{"ok": true}, nil)
}
