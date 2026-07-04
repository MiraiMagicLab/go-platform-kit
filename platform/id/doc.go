// Package id provides a pluggable ID generator.
//
// Use [UUIDGenerator] for production:
//
//	var gen id.Generator = id.UUIDGenerator{}
//	newID := gen.New()
//
// Implement [Generator] for custom ID schemes (ULID, KSUID, etc.).
package id
