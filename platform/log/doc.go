// Package log defines a minimal logging interface for platform capabilities.
//
// Libraries must not force a logging backend on consumers. Pass a Logger via
// capability options; the default is a no-op implementation.
package log
