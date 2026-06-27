// Package authgin provides optional reference Gin routes for quick prototypes.
// Production apps should prefer host-owned handlers calling [auth.Auth] use-case methods.
package authgin

import (
	"github.com/gin-gonic/gin"

	"github.com/MiraiMagicLab/go-platform-kit/auth"
)

// MountAll registers the default reference auth HTTP routes on r.
func MountAll(a *auth.Auth, r gin.IRouter) {
	a.MountReferenceAll(r)
}
