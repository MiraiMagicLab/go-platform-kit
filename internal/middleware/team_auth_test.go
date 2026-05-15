package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func TestRequireTeamAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		level      string
		appAccess  string
		wantAbort  bool
	}{
		{"read ok on read", "read", "read", false},
		{"read ok on write", "read", "write", false},
		{"read fail on empty", "read", "", true},
		{"write ok on write", "write", "write", false},
		{"write fail on read", "write", "read", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			setTeamAuth(c, TeamAuth{ActorUserID: uuid.New(), AppAccess: tc.appAccess, Capabilities: []string{"cron:read"}})

			RequireTeamAccess(tc.level)(c)
			if c.IsAborted() != tc.wantAbort {
				t.Fatalf("abort=%v want=%v", c.IsAborted(), tc.wantAbort)
			}
		})
	}
}

func TestRequireTeamCapability(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	setTeamAuth(c, TeamAuth{
		ActorUserID:  uuid.New(),
		AppAccess:    "write",
		Capabilities: []string{"cron:read"},
	})

	RequireTeamCapability("cron:write")(c)
	if !c.IsAborted() {
		t.Fatal("expected forbidden")
	}
}
