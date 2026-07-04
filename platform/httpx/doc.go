// Package httpx provides a stable JSON API envelope, pagination helpers, and recovery
// middleware for MiraiMagicLab backend services.
//
// Error codes and the message registry have moved to [github.com/MiraiMagicLab/go-platform-kit/platform/errors].
// Pagination types and query parsers have moved to [github.com/MiraiMagicLab/go-platform-kit/platform/pagination].
//
// All symbols are re-exported here for backward compatibility, but new code should
// import the dedicated packages directly.
//
// Use [WriteError] to chain domain-specific error translation.
// Use [Recovery] middleware to convert panics into internal error responses.
package httpx
