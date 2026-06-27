package log_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/MiraiMagicLab/go-platform-kit/platform/log"
)

func TestNewSlogNilReturnsNoop(t *testing.T) {
	l := log.NewSlog(nil)
	require.IsType(t, log.Noop{}, l)
}

func TestNewSlogWrapsLogger(t *testing.T) {
	l := log.NewSlog(slog.Default())
	require.IsType(t, log.Slog{}, l)
}
