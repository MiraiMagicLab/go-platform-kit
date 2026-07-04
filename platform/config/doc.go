// Package config loads and validates shared application and infrastructure
// configuration for MiraiMagicLab backend applications.
//
// Auth-specific configuration (JWT secrets, OAuth credentials, etc.) lives in
// the auth package to keep platform/* free of auth coupling.
//
// Capabilities receive opened clients/pools from the host; they do not read
// environment variables directly. Use [FromEnv] explicitly when desired.
package config
