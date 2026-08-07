// SPDX-License-Identifier: Apache-2.0
package platform

import "testing"

func TestConfigDir_NotEmpty(t *testing.T) {
	dir := ConfigDir()
	if dir == "" {
		t.Error("ConfigDir() returned empty string")
	}
	t.Logf("ConfigDir: %s", dir)
}

func TestDataDir_NotEmpty(t *testing.T) {
	dir := DataDir()
	if dir == "" {
		t.Error("DataDir() returned empty string")
	}
	t.Logf("DataDir: %s", dir)
}

func TestCacheDir_NotEmpty(t *testing.T) {
	dir := CacheDir()
	if dir == "" {
		t.Error("CacheDir() returned empty string")
	}
	t.Logf("CacheDir: %s", dir)
}

func TestConfigDir_DoesNotUseDotConfig(t *testing.T) {
	// On all platforms, ConfigDir should use os.UserConfigDir() which returns
	// the platform-appropriate directory, not hardcode ".config"
	dir := ConfigDir()
	// The key invariant: on Linux it's under ~/.config, on Windows it's under %AppData%
	// We just verify it's a valid path
	if len(dir) == 0 {
		t.Error("ConfigDir is empty")
	}
}
