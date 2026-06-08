package domain

import (
	"time"

	"github.com/google/uuid"
)

// Role represents a named role in the RBAC system.
type Role struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Permission represents a named permission in the RBAC system.
type Permission struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}
