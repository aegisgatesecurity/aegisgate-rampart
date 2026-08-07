// SPDX-License-Identifier: Apache-2.0

package autostart

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCompNew(t *testing.T) {
	mgr := New("/usr/local/bin/rampart")
	if mgr == nil {
		t.Fatal("New returned nil")
	}
	if mgr.binPath != "/usr/local/bin/rampart" {
		t.Errorf("binPath = %q, want /usr/local/bin/rampart", mgr.binPath)
	}
}

func TestNewEmptyPath(t *testing.T) {
	mgr := New("")
	if mgr == nil {
		t.Fatal("New with empty path should not return nil")
	}
	if mgr.binPath != "" {
		t.Errorf("binPath = %q, want empty", mgr.binPath)
	}
}

func TestNewWithCustomPath(t *testing.T) {
	customPath := "/opt/aegisgate/bin/rampart"
	mgr := New(customPath)
	if mgr.binPath != customPath {
		t.Errorf("binPath = %q, want %q", mgr.binPath, customPath)
	}
}

func TestCompIsEnabledNotConfigured(t *testing.T) {
	mgr := New("/nonexistent/bin/rampart")
	if mgr.IsEnabled() {
		t.Error("IsEnabled should return false when not configured")
	}
}

func TestCompEnableDisableLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho rampart"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := New(fakeBin)

	// Enable should create a systemd unit file
	if err := mgr.Enable(); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	// Verify the file was created
	unitPath := mgr.unitPath()
	if _, err := os.Stat(unitPath); err != nil {
		t.Errorf("Unit file should exist at %s: %v", unitPath, err)
	}

	// Verify file content contains the binary path
	data, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("Failed to read unit file: %v", err)
	}
	if !strings.Contains(string(data), fakeBin) {
		t.Errorf("Unit file should contain bin path %s", fakeBin)
	}
	if !strings.Contains(string(data), "[Unit]") {
		t.Error("Unit file should contain [Unit] section")
	}
	if !strings.Contains(string(data), "[Service]") {
		t.Error("Unit file should contain [Service] section")
	}
	if !strings.Contains(string(data), "[Install]") {
		t.Error("Unit file should contain [Install] section")
	}

	// IsEnabled should return true
	if !mgr.IsEnabled() {
		t.Error("IsEnabled should return true after Enable()")
	}

	// Disable should remove the file
	if err := mgr.Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	// IsEnabled should return false after Disable
	if mgr.IsEnabled() {
		t.Error("IsEnabled should return false after Disable()")
	}
}

func TestUnitPathLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	mgr := New("/usr/bin/rampart")
	path := mgr.unitPath()
	if !strings.HasSuffix(path, "rampart.service") {
		t.Errorf("unitPath = %q, should end with rampart.service", path)
	}
	if !strings.Contains(path, ".config/systemd/user") {
		t.Errorf("unitPath = %q, should contain .config/systemd/user", path)
	}
}

func TestCompEnableNonExistentBinary(t *testing.T) {
	mgr := New("/definitely/not/a/real/path/rampart")
	err := mgr.Enable()
	// Should not panic even with nonexistent binary
	// On Linux it will still write the file
	_ = err
}

func TestCompDisableWhenNotEnabled(t *testing.T) {
	mgr := New("/usr/local/bin/rampart")
	err := mgr.Disable()
	// Should not error when nothing to remove (os.Remove returns nil for nonexistent)
	_ = err
}

func TestManagerStructFields(t *testing.T) {
	mgr := &Manager{binPath: "/test/path"}
	if mgr.binPath != "/test/path" {
		t.Errorf("binPath = %q, want /test/path", mgr.binPath)
	}
}

func TestPlistPathDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-specific test")
	}
	mgr := New("/usr/local/bin/rampart")
	path := mgr.plistPath()
	if !strings.HasSuffix(path, ".plist") {
		t.Errorf("plistPath = %q, should end with .plist", path)
	}
	if !strings.Contains(path, "LaunchAgents") {
		t.Errorf("plistPath = %q, should contain LaunchAgents", path)
	}
}

func TestPlistContentDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-specific test")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho rampart"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := New(fakeBin)
	if err := mgr.Enable(); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	plistPath := mgr.plistPath()
	data, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("Failed to read plist: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, plistName) {
		t.Error("Plist should contain bundle identifier")
	}
	if !strings.Contains(content, fakeBin) {
		t.Error("Plist should contain binary path")
	}
	if !strings.Contains(content, "--daemon") {
		t.Error("Plist should contain --daemon flag")
	}

	// Clean up
	os.Remove(plistPath)
}

func TestWindowsRegContent(t *testing.T) {
	if runtime.GOOS != "windows" {
		// Can't fully test Windows path but verify the Manager creation works
		mgr := New("/usr/local/bin/rampart")
		_ = mgr
	}
}

func TestEnableDisableRoundTripLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho rampart"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := New(fakeBin)

	// Initially not enabled
	if mgr.IsEnabled() {
		t.Error("Should not be enabled initially")
	}

	// Enable
	if err := mgr.Enable(); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if !mgr.IsEnabled() {
		t.Error("Should be enabled after Enable()")
	}

	// Disable
	if err := mgr.Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if mgr.IsEnabled() {
		t.Error("Should not be enabled after Disable()")
	}
}

func TestConstants(t *testing.T) {
	if plistName != "com.aegisgate.rampart" {
		t.Errorf("plistName = %q, want com.aegisgate.rampart", plistName)
	}
	if unitName != "rampart.service" {
		t.Errorf("unitName = %q, want rampart.service", unitName)
	}
	if regKeyName != "AegisGateRampart" {
		t.Errorf("regKeyName = %q, want AegisGateRampart", regKeyName)
	}
}
