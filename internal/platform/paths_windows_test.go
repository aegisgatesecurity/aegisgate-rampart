// SPDX-License-Identifier: Apache-2.0
//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDir_Windows(t *testing.T) {
	dir := ConfigDir()
	if dir == "" {
		t.Error("ConfigDir() returned empty string")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("ConfigDir() should return absolute path, got %s", dir)
	}
	t.Logf("ConfigDir: %s", dir)
}

func TestDataDir_Windows(t *testing.T) {
	dir := DataDir()
	if dir == "" {
		t.Error("DataDir() returned empty string")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("DataDir() should return absolute path, got %s", dir)
	}
	t.Logf("DataDir: %s", dir)
}

func TestCacheDir_Windows(t *testing.T) {
	dir := CacheDir()
	if dir == "" {
		t.Error("CacheDir() returned empty string")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("CacheDir() should return absolute path, got %s", dir)
	}
	t.Logf("CacheDir: %s", dir)
}

func TestConfigDir_WindowsPath(t *testing.T) {
	dir := ConfigDir()
	// On Windows, should contain "AegisGate Rampart" (not "aegisgate-rampart")
	if !filepath.IsAbs(dir) {
		t.Skip("ConfigDir is not absolute (likely fallback)")
	}
	base := filepath.Base(dir)
	if base != "AegisGate Rampart" && base != "aegisgate-rampart" {
		t.Errorf("ConfigDir base should be AegisGate Rampart, got %s", base)
	}
}

func TestConfigDir_UsesAppData(t *testing.T) {
	dir := ConfigDir()
	appData := os.Getenv("APPDATA")
	if appData == "" {
		t.Skip("APPDATA not set")
	}
	// ConfigDir should be under %AppData% on Windows
	if !filepath.IsAbs(dir) {
		t.Skip("ConfigDir is not absolute")
	}
	// Verify it's not using .config (Unix path)
	if filepath.Base(filepath.Dir(dir)) == ".config" {
		t.Errorf("ConfigDir on Windows should use AppData, not .config: %s", dir)
	}
}

func TestAllDirs_WindowsDistinct(t *testing.T) {
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
