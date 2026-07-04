package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/platform/config"
	"github.com/MiraiMagicLab/go-platform-kit/platform/mail"
	"github.com/MiraiMagicLab/go-platform-kit/platform/storage"
)

func TestFromEnvAppConfig(t *testing.T) {
	t.Setenv("APP_NAME", "my-service")
	t.Setenv("PORT", "3000")
	t.Setenv("APP_ENV", "staging")
	cfg := config.FromEnv()
	require.Equal(t, "my-service", cfg.App.Name)
	require.Equal(t, "3000", cfg.App.Port)
	require.Equal(t, "staging", cfg.App.Env)
}

func TestFromEnvR2Keys(t *testing.T) {
	t.Setenv("R2_ACCOUNT_ID", "acc123")
	t.Setenv("R2_BUCKET", "assets")
	t.Setenv("R2_ACCESS_KEY", "access")
	t.Setenv("R2_SECRET_KEY", "secret")
	t.Setenv("R2_PUBLIC_BASE", "https://cdn.example.com")
	cfg := config.FromEnv()
	require.Equal(t, "acc123", cfg.Infra.Storage.AccountID)
	require.Equal(t, "assets", cfg.Infra.Storage.Bucket)
	require.Equal(t, "access", cfg.Infra.Storage.AccessKey)
	require.Equal(t, "secret", cfg.Infra.Storage.SecretKey)
	require.Equal(t, "https://cdn.example.com", cfg.Infra.Storage.PublicBase)
}

func TestValidateConfiguredSections(t *testing.T) {
	cfg := config.Config{
		Infra: config.Infra{
			Storage: storage.Config{
				AccountID: "acc",
				Bucket:    "assets",
				AccessKey: "key",
				SecretKey: "secret",
			},
			Mail: mail.Config{
				Host: "smtp.example.com",
				Port: 587,
				User: "user",
				Pass: "pass",
				From: "noreply@example.com",
			},
		},
	}
	require.NoError(t, cfg.Validate())
}
