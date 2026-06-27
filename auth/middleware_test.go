package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRequireAccess_noneModePassThrough(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := &Auth{cfg: Config{AuthZ: AuthZConfig{Mode: AuthZNone}}}

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(a.RequireAccess("anything"))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	r.HandleContext(c)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAccess_rbacModeRequiresValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := &Auth{cfg: Config{AuthZ: AuthZConfig{Mode: AuthZRbac}}}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	a.RequireAccess()(c)
	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, w.Code)
}
