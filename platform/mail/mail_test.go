package mail_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/platform/mail"
)

func TestConfigValidate(t *testing.T) {
	err := mail.Config{Host: "smtp.example.com"}.Validate()
	require.Error(t, err)

	err = mail.Config{
		Host: "smtp.example.com",
		Port: 587,
		User: "user",
		Pass: "pass",
		From: "noreply@example.com",
	}.Validate()
	require.NoError(t, err)
}

func TestOpenRequiresConfig(t *testing.T) {
	_, err := mail.Open(mail.Config{})
	require.ErrorIs(t, err, mail.ErrNotConfigured)
}
