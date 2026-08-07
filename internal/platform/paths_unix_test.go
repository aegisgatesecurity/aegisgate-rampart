// SPDX-License-Identifier: Apache-2.0
//go:build !windows

package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConfigDir_UnixLike(t *testing.T) {
	dir := ConfigDir()
	if dir == "" {
		t.Error("ConfigDir() returned empty string")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("ConfigDir() should return absolute path, got %s", dir)
	}
	t.Logf("ConfigDir: %s", dir)
}

func TestDataDir_UnixLike(t *testing.T) {
	dir := DataDir()
	if dir == "" {
		t.Error("DataDir() returned empty string")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("DataDir() should return absolute path, got %s", dir)
	}
	t.Logf("DataDir: %s", dir)
}

func TestCacheDir_UnixLike(t *testing.T) {
	dir := CacheDir()
	if dir == "" {
		t.Error("CacheDir() returned empty string")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("CacheDir() should return absolute path, got %s", dir)
	}
	t.Logf("CacheDir: %s", dir)
}

func TestConfigDir_ContainsAegisGate(t *testing.T) {
	dir := ConfigDir()
	if !filepath.IsAbs(dir) {
		t.Skip("ConfigDir is not absolute (likely fallback)")
	}
	base := filepath.Base(dir)
	if base != "aegisgate-rampart" && base != "AegisGate Rampart" {
		t.Errorf("ConfigDir base should be aegisgate-rampart, got %s", base)
	}
}

func TestConfigDir_MacOSPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}
	dir := ConfigDir()
	// On macOS, os.UserConfigDir() returns ~/Library/Application Support
	if !filepath.IsAbs(dir) {
		t.Errorf("ConfigDir should be absolute on macOS, got %s", dir)
	}
	// Should NOT contain .config on macOS
	if filepath.Base(filepath.Dir(dir)) == ".config" {
		t.Errorf("ConfigDir on macOS should use Library/Application Support, not .config: %s", dir)
	}
}

func TestConfigDir_LinuxPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	dir := ConfigDir()
	// On Linux, should be under ~/.config/aegisgate-rampart
	home, _ := os.UserHomeDir()
	expected := filepath.Join(home, ".config", "aegisgate-rampart")
	if dir != expected {
		t.Errorf("ConfigDir on Linux = %s, want %s", dir, expected)
	}
}

func TestAllDirs_AreDistinct(t *testing.T) {
	cfg := ConfigDir()
	data := DataDir()
	cache := CacheDir()
	if cfg == data {
		t.Error("ConfigDir and DataDir should be distinct")
	}
	if cfg == cache {
		t.Error("ConfigDir and CacheDir should be distinct")
	}
	if data == cache {
		t.Error("DataDir and CacheDir should be distinct")
	}
}
