package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotConfigured is returned when R2 storage is used without required settings.
var ErrNotConfigured = errors.New("storage: R2 not configured")

// PutOptions describes optional upload metadata.
type PutOptions struct {
	ContentType string
}

// ObjectStore uploads and serves objects from a Cloudflare R2 bucket.
type ObjectStore interface {
	Put(ctx context.Context, key string, body io.Reader, opts PutOptions) error
	Delete(ctx context.Context, key string) error
	URL(key string) string
	SignedURL(ctx context.Context, key string, expiry time.Duration) (string, error)
}

// Config describes Cloudflare R2 connection settings.
type Config struct {
	AccountID  string
	Bucket     string
	AccessKey  string
	SecretKey  string
	PublicBase string
	Endpoint   string
}

// IsConfigured reports whether required R2 settings are present.
func (c Config) IsConfigured() bool {
	return c.Bucket != "" && c.AccessKey != "" && c.SecretKey != "" && (c.AccountID != "" || c.Endpoint != "")
}

// Validate checks required R2 fields.
func (c Config) Validate() error {
	if !c.IsConfigured() {
		return ErrNotConfigured
	}
	return nil
}

// Open returns an R2-backed [ObjectStore].
func Open(ctx context.Context, cfg Config) (ObjectStore, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return openR2(ctx, cfg)
}

func normalizeKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("storage: key is required")
	}
	key = strings.TrimPrefix(key, "/")
	key = filepath.Clean(key)
	if key == "." || strings.HasPrefix(key, "..") {
		return "", fmt.Errorf("storage: invalid key %q", key)
	}
	return filepath.ToSlash(key), nil
}
