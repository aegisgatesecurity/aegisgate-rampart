// SPDX-License-Identifier: Apache-2.0
//go:build !windows

package platform

import (
	"os"
	"path/filepath"
	"runtime"
)

// ConfigDir returns the platform-appropriate configuration directory.
// On Linux/macOS: ~/.config/aegisgate-rampart
// On Windows: %AppData%\AegisGate Rampart (see paths_windows.go)
func ConfigDir() string {
	// os.UserConfigDir() returns ~/.config on Linux,
	// ~/Library/Application Support on macOS
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "aegisgate-rampart")
	}
	// Fallback
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".config", "aegisgate-rampart")
}

// DataDir returns the platform-appropriate data directory.
// On Linux: ~/.local/share/aegisgate-rampart
// On macOS: ~/Library/Application Support/aegisgate-rampart (same as ConfigDir)
// On Windows: %AppData%\AegisGate Rampart\data (see paths_windows.go)
func DataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ConfigDir()
	}
	switch runtime.GOOS {
	case "darwin":
		// macOS: data lives alongside config in ~/Library/Application Support
		return filepath.Join(home, "Library", "Application Support", "aegisgate-rampart")
	default:
		// Linux: data in ~/.local/share, config in ~/.config
		return filepath.Join(home, ".local", "share", "aegisgate-rampart")
	}
}

// CacheDir returns the platform-appropriate cache directory.
func CacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "aegisgate-rampart")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".cache", "aegisgate-rampart")
}
