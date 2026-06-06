package utils

import "testing"

func TestDeviceNameFromUA(t *testing.T) {
	tests := []struct {
		ua       string
		contains string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Chrome on Windows"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "Safari on iPhone"},
		{"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "iPad"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "macOS"},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Linux"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", "Firefox on Windows"},
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36", "Chrome on Android"},
		{"", ""},
	}

	for _, tt := range tests {
		name := DeviceNameFromUA(tt.ua)
		if tt.contains != "" && !contains(name, tt.contains) {
			t.Errorf("UA=%q: expected to contain %q, got %q", tt.ua, tt.contains, name)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestEmailValidator(t *testing.T) {
	v := DefaultEmailValidator

	valid := []string{
		"test@gmail.com",
		"user.name@domain.org",
		"a@b.co",
	}
	for _, e := range valid {
		if !v(e) {
			t.Errorf("expected %q to be valid", e)
		}
	}

	invalid := []string{
		"",
		"notanemail",
		"@gmail.com",
		"test@",
		"test",
	}
	for _, e := range invalid {
		if v(e) {
			t.Errorf("expected %q to be invalid", e)
		}
	}
}
