package id

import "github.com/google/uuid"

// Generator produces unique identifiers.
type Generator interface {
	New() string
}

// UUIDGenerator produces UUID v4 strings.
type UUIDGenerator struct{}

func (UUIDGenerator) New() string { return uuid.NewString() }
