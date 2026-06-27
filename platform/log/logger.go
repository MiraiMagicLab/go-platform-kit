package log

// Logger is the minimal logging contract used across platform capabilities.
// Implementations should be safe for concurrent use.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// Noop discards all log output. It is the default when no logger is configured.
type Noop struct{}

func (Noop) Info(msg string, args ...any)  {}
func (Noop) Warn(msg string, args ...any)  {}
func (Noop) Error(msg string, args ...any) {}
