package storage_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/platform/storage"
)

func TestR2ConfigValidate(t *testing.T) {
	err := storage.Config{}.Validate()
	require.ErrorIs(t, err, storage.ErrNotConfigured)

	err = storage.Config{Bucket: "assets", AccessKey: "key", SecretKey: "secret", AccountID: "acc"}.Validate()
	require.NoError(t, err)

	err = storage.Config{Bucket: "assets", AccessKey: "key", SecretKey: "secret", Endpoint: "https://example.r2.cloudflarestorage.com"}.Validate()
	require.NoError(t, err)
}

func TestR2ConfigIsConfigured(t *testing.T) {
	require.False(t, storage.Config{Bucket: "b"}.IsConfigured())
	require.True(t, storage.Config{Bucket: "b", AccessKey: "k", SecretKey: "s", AccountID: "a"}.IsConfigured())
}

func TestOpenRequiresR2Config(t *testing.T) {
	_, err := storage.Open(t.Context(), storage.Config{})
	require.Error(t, err)
}
