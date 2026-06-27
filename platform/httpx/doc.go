// Package httpx provides a stable JSON API envelope and platform error codes (M00xxxx)
// for MiraiMagicLab backend services.
//
// Host applications and platform capabilities should use the same response shape so
// clients can rely on consistent success/error codes across products.
//
// Use [ErrorMapper] and [WriteError] to chain domain-specific error translation.
// Use [Recovery] middleware to convert panics into internal error responses.
package httpx
