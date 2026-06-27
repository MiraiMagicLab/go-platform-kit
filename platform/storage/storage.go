package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotConfigured is returned when storage is used without configuration.
var ErrNotConfigured = errors.New("storage: not configured")

// PutOptions describes optional upload metadata.
type PutOptions struct {
	ContentType string
}

// ObjectStore uploads and serves objects from a bucket.
type ObjectStore interface {
	Put(ctx context.Context, key string, body io.Reader, opts PutOptions) error
	Delete(ctx context.Context, key string) error
	URL(key string) string
	SignedURL(ctx context.Context, key string, expiry time.Duration) (string, error)
}

// Config describes object storage connection settings.
type Config struct {
	Provider   string // "r2", "s3", "local"
	Bucket     string
	AccountID  string
	AccessKey  string
	SecretKey  string
	PublicBase string
}

// IsConfigured reports whether enough settings exist to open a store.
func (c Config) IsConfigured() bool {
	return c.Provider != "" && c.Bucket != ""
}

// Open returns an ObjectStore for cfg. R2/S3 providers will be implemented in a
// follow-up change; local/noop is returned for now when not configured.
func Open(ctx context.Context, cfg Config) (ObjectStore, error) {
	if !cfg.IsConfigured() {
		return nil, ErrNotConfigured
	}
	return &noopStore{publicBase: cfg.PublicBase}, nil
}

type noopStore struct {
	publicBase string
}

func (n *noopStore) Put(ctx context.Context, key string, body io.Reader, opts PutOptions) error {
	return ErrNotConfigured
}

func (n *noopStore) Delete(ctx context.Context, key string) error {
	return ErrNotConfigured
}

func (n *noopStore) URL(key string) string {
	if n.publicBase == "" {
		return key
	}
	return n.publicBase + "/" + key
}

func (n *noopStore) SignedURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	return "", ErrNotConfigured
}
