package errors

import (
	"fmt"
	"strings"
	"sync"
)

var (
	mu          sync.RWMutex
	allMessages = make(map[string]string)
)

func init() {
	for k, v := range commonMessages {
		allMessages[k] = v
	}
}

// RegisterMessages adds domain-specific error code-to-message mappings to the global registry.
// This is called at startup by host applications to register product-specific error messages.
// Empty keys and values are silently ignored.
// This function is safe for concurrent use.
func RegisterMessages(entries map[string]string) {
	mu.Lock()
	defer mu.Unlock()
	for k, v := range entries {
		if k != "" && v != "" {
			allMessages[k] = v
		}
	}
}

// DefaultMessage returns the human-readable message for the given error code.
// Returns an empty string if the code is not registered.
// This function is safe for concurrent use.
func DefaultMessage(code string) string {
	mu.RLock()
	defer mu.RUnlock()
	return allMessages[code]
}

// AllRegisteredCodes returns a snapshot of all registered error code-to-message mappings.
// This function is safe for concurrent use.
func AllRegisteredCodes() map[string]string {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]string, len(allMessages))
	for k, v := range allMessages {
		out[k] = v
	}
	return out
}

// RenderMessage substitutes positional placeholders ({0}, {1}, …) in a template string.
func RenderMessage(template string, args ...interface{}) string {
	out := template
	for i, v := range args {
		out = strings.ReplaceAll(out, fmt.Sprintf("{%d}", i), fmt.Sprint(v))
	}
	return out
}
