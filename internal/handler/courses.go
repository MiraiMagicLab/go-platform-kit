package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type CoursesHandler struct{}

func NewCoursesHandler() *CoursesHandler { return &CoursesHandler{} }

func (h *CoursesHandler) CreateCourse(c *gin.Context) {
	// Example protected endpoint; in a real service this likely belongs to another microservice.
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "course created (example)"})
}
