// Package authkit is the primary embedded API for go-platform-kit: a Gin + PostgreSQL
// (+ optional Redis) authentication, RBAC, MFA, OAuth, and email verification toolkit.
//
// # Module structure
//
// Public API surface (consumers may import, semver-stable):
//
//	github.com/MiraiMagicLab/go-platform-kit/v2/pkg/authkit   — New, Mount*, middleware exports
//	github.com/MiraiMagicLab/go-platform-kit/v2/pkg/response  — JSON response envelope (Success / Fail / FailCode)
//	github.com/MiraiMagicLab/go-platform-kit/v2/pkg/token     — JWT creation and parsing
//	github.com/MiraiMagicLab/go-platform-kit/v2/pkg/ports     — Repository and service interfaces
//	github.com/MiraiMagicLab/go-platform-kit/v2/pkg/domain    — Domain types with behavior
//
// internal/ — implementation details, not importable outside this module:
//
//	internal/auth          — Authentication use cases (register, login, refresh, logout)
//	internal/session       — Session management
//	internal/mfa           — TOTP multi-factor authentication
//	internal/oauth         — OAuth2 flows (Google, Facebook)
//	internal/rbac          — Role and permission management
//	internal/email         — Email verification and password reset
//	internal/http          — HTTP handlers and middleware
//	internal/storage       — PostgreSQL repository implementations
//	internal/security      — AES-GCM encryption for secrets at rest
//
// Schema and examples:
//
//	migrations/            — SQL migration files
//	examples/embedded      — Minimal embedded usage example
//
// Lifecycle hooks can be set on Config.Hooks to run side-effects (e.g. notifications)
// asynchronously after session issuance without blocking the HTTP response.
package authkit
