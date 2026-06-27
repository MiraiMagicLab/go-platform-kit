// Package config loads and validates shared infrastructure configuration for
// MiraiMagicLab backend applications.
//
// Capabilities receive opened clients/pools from the host; they do not read
// environment variables directly. Use [FromEnv] explicitly when desired.
package config
