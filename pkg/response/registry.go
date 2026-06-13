package response

import "sync"

var (
	mu          sync.RWMutex
	allMessages = make(map[string]string)
)

func init() {
	for k, v := range commonMessages {
		allMessages[k] = v
	}
}

func RegisterMessages(entries map[string]string) {
	mu.Lock()
	defer mu.Unlock()
	for k, v := range entries {
		if k != "" && v != "" {
			allMessages[k] = v
		}
	}
}

func DefaultMessage(code string) string {
	mu.RLock()
	defer mu.RUnlock()
	return allMessages[code]
}

func AllRegisteredCodes() map[string]string {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]string, len(allMessages))
	for k, v := range allMessages {
		out[k] = v
	}
	return out
}
