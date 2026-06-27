package log

import "log/slog"

// Slog adapts a [slog.Logger] to the platform [Logger] interface.
type Slog struct {
	l *slog.Logger
}

// NewSlog wraps l. If l is nil, a no-op logger is returned.
func NewSlog(l *slog.Logger) Logger {
	if l == nil {
		return Noop{}
	}
	return Slog{l: l}
}

func (s Slog) Info(msg string, args ...any)  { s.l.Info(msg, args...) }
func (s Slog) Warn(msg string, args ...any)  { s.l.Warn(msg, args...) }
func (s Slog) Error(msg string, args ...any) { s.l.Error(msg, args...) }
