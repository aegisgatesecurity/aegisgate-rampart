// SPDX-License-Identifier: Apache-2.0
//go:build windows

package platform

import (
	"os"
	"path/filepath"
)

// ConfigDir returns the platform-appropriate configuration directory.
// On Windows: %AppData%\AegisGate Rampart
// On Linux/macOS: ~/.config/aegisgate-rampart (see paths_unix.go)
func ConfigDir() string {
	// os.UserConfigDir() returns %AppData% on Windows
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "AegisGate Rampart")
	}
	// Fallback: use LOCALAPPDATA
	if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
		return filepath.Join(dir, "AegisGate Rampart")
	}
	// Last resort
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, "AppData", "Local", "AegisGate Rampart")
}

// DataDir returns the platform-appropriate data directory.
// On Windows: %AppData%\AegisGate Rampart\data
func DataDir() string {
	return filepath.Join(ConfigDir(), "data")
}

// CacheDir returns the platform-appropriate cache directory.
// On Windows: %LocalAppData%\AegisGate Rampart\cache
func CacheDir() string {
	if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
		return filepath.Join(dir, "AegisGate Rampart", "cache")
	}
	return filepath.Join(ConfigDir(), "cache")
}
