package util

import (
	"strings"
)

// DeviceNameFromUA parses a User-Agent string and returns a human-readable device name.
func DeviceNameFromUA(ua string) string {
	if ua == "" {
		return ""
	}
	browser := detectBrowser(ua)
	os := detectOS(ua)
	if browser == "" && os == "" {
		return truncate(ua, 64)
	}
	if browser == "" {
		return os
	}
	if os == "" {
		return browser
	}
	return browser + " on " + os
}

func detectBrowser(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "edg/"):
		return "Edge"
	case strings.Contains(lower, "opr/"), strings.Contains(lower, "opera"):
		return "Opera"
	case strings.Contains(lower, "chrome") && !strings.Contains(lower, "chromium"):
		return "Chrome"
	case strings.Contains(lower, "safari") && !strings.Contains(lower, "chrome"):
		return "Safari"
	case strings.Contains(lower, "firefox"):
		return "Firefox"
	case strings.Contains(lower, "chromium"):
		return "Chromium"
	case strings.Contains(lower, "msie"), strings.Contains(lower, "trident"):
		return "IE"
	default:
		return ""
	}
}

func detectOS(ua string) string {
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad") || strings.Contains(lower, "ipod"):
		return detectIOSDevice(ua)
	case strings.Contains(lower, "android"):
		return "Android"
	case strings.Contains(lower, "windows nt 11") || strings.Contains(lower, "windows nt 10") || strings.Contains(lower, "windows nt 6"):
		return "Windows"
	case strings.Contains(lower, "mac os x"):
		return "macOS"
	case strings.Contains(lower, "linux"):
		if strings.Contains(lower, "ubuntu") {
			return "Ubuntu"
		}
		return "Linux"
	case strings.Contains(lower, "cros"):
		return "Chrome OS"
	default:
		return ""
	}
}

func detectIOSDevice(ua string) string {
	if strings.Contains(strings.ToLower(ua), "ipad") {
		return "iPad"
	}
	if strings.Contains(strings.ToLower(ua), "iphone") {
		return "iPhone"
	}
	if strings.Contains(strings.ToLower(ua), "ipod") {
		return "iPod"
	}
	return "iOS"
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
