package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-auth-lib/internal/middleware"
	"github.com/MiraiMagicLab/go-auth-lib/pkg/response"
	"github.com/MiraiMagicLab/go-auth-lib/internal/services"
)

type MFAHandler struct {
	mfa   *services.MFAService
	audit *services.AuditService
}

func NewMFAHandler(mfa *services.MFAService, audit *services.AuditService) *MFAHandler {
	return &MFAHandler{mfa: mfa, audit: audit}
}

func (h *MFAHandler) Setup(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, "Unauthorized", nil)
		return
	}

	out, err := h.mfa.SetupTOTP(c.Request.Context(), userID, userID.String())
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeMFASetupFailed, "Could not setup MFA", nil)
		h.audit.Log(c.Request.Context(), &userID, "mfa.setup", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	h.audit.Log(c.Request.Context(), &userID, "mfa.setup", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "MFA setup initialized", out)
}

type mfaEnableReq struct {
	Code string `json:"code" binding:"required"`
}

func (h *MFAHandler) Enable(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, "Unauthorized", nil)
		return
	}
	var req mfaEnableReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeCommonBadRequest, "Invalid request body", nil)
		return
	}
	if err := h.mfa.EnableTOTP(c.Request.Context(), userID, req.Code); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeMFAEnableFailed, "Invalid OTP", nil)
		h.audit.Log(c.Request.Context(), &userID, "mfa.enable", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	h.audit.Log(c.Request.Context(), &userID, "mfa.enable", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "MFA enabled", gin.H{"ok": true})
}

func (h *MFAHandler) Disable(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, "Unauthorized", nil)
		return
	}
	if err := h.mfa.Disable(c.Request.Context(), userID); err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeMFADisableFailed, "Could not disable MFA", nil)
		h.audit.Log(c.Request.Context(), &userID, "mfa.disable", "failed", c.ClientIP(), c.Request.UserAgent(), nil)
		return
	}
	h.audit.Log(c.Request.Context(), &userID, "mfa.disable", "success", c.ClientIP(), c.Request.UserAgent(), nil)
	response.Success(c, http.StatusOK, "MFA disabled", gin.H{"ok": true})
}
