package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tienh/authsvc/internal/middleware"
	"github.com/tienh/authsvc/internal/response"
	"github.com/tienh/authsvc/internal/service"
)

type MFAHandler struct {
	mfa *service.MFAService
}

func NewMFAHandler(mfa *service.MFAService) *MFAHandler { return &MFAHandler{mfa: mfa} }

func (h *MFAHandler) Setup(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		response.Fail(c, http.StatusUnauthorized, response.CodeAuthUnauthorized, "Unauthorized", nil)
		return
	}

	out, err := h.mfa.SetupTOTP(c.Request.Context(), userID, userID.String())
	if err != nil {
		response.Fail(c, http.StatusBadRequest, response.CodeMFASetupFailed, "Could not setup MFA", nil)
		return
	}
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
		return
	}
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
		return
	}
	response.Success(c, http.StatusOK, "MFA disabled", gin.H{"ok": true})
}
