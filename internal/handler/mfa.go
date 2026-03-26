package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tienh/authsvc/internal/middleware"
	"github.com/tienh/authsvc/internal/service"
)

type MFAHandler struct {
	mfa *service.MFAService
}

func NewMFAHandler(mfa *service.MFAService) *MFAHandler { return &MFAHandler{mfa: mfa} }

func (h *MFAHandler) Setup(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	out, err := h.mfa.SetupTOTP(c.Request.Context(), userID, userID.String())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not setup mfa"})
		return
	}
	c.JSON(http.StatusOK, out)
}

type mfaEnableReq struct {
	Code string `json:"code" binding:"required"`
}

func (h *MFAHandler) Enable(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req mfaEnableReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.mfa.EnableTOTP(c.Request.Context(), userID, req.Code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid otp"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *MFAHandler) Disable(c *gin.Context) {
	userID, ok := middleware.UserIDFromCtx(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if err := h.mfa.Disable(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not disable mfa"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
