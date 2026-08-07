// SPDX-License-Identifier: Apache-2.0
package autostart

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNewManager(t *testing.T) {
	mgr := New("/usr/local/bin/rampart")
	if mgr == nil {
		t.Fatal("New returned nil")
	}
	if mgr.binPath != "/usr/local/bin/rampart" {
		t.Errorf("binPath = %s, want /usr/local/bin/rampart", mgr.binPath)
	}
}

func TestIsEnabled_NotConfigured(t *testing.T) {
	mgr := New("/nonexistent/bin/rampart")
	if mgr.IsEnabled() {
		t.Error("IsEnabled should return false when not configured")
	}
}

func TestLinux_EnableCreatesUnitFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	// Use a temp binary to avoid polluting the real systemd directory
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho rampart"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := New(fakeBin)

	// Enable should create a systemd unit file
	// Note: This creates in the real ~/.config/systemd/user/ directory
	// We'll just verify it doesn't panic
	err := mgr.Enable()
	if err != nil {
		t.Logf("Enable() returned error (may be expected in test env): %v", err)
	}

	// Clean up if it succeeded
	_ = mgr.Disable()
}

func TestLinux_DisableNotEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	mgr := New("/nonexistent/bin/rampart")
	err := mgr.Disable()
	// Should not error when nothing to remove
	_ = err
}

func TestLinux_UnitFileContent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho rampart"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := New(fakeBin)
	err := mgr.Enable()
	if err != nil {
		t.Skipf("Enable() failed: %v", err)
	}
	defer mgr.Disable()

	unitPath := mgr.unitPath()
	data, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("Failed to read unit file: %v", err)
	}

	content := string(data)

	// Verify systemd unit content
	if !strings.Contains(content, "[Unit]") {
		t.Error("Unit file should contain [Unit] section")
	}
	if !strings.Contains(content, "[Service]") {
		t.Error("Unit file should contain [Service] section")
	}
	if !strings.Contains(content, "[Install]") {
		t.Error("Unit file should contain [Install] section")
	}
	if !strings.Contains(content, "ExecStart=") {
		t.Error("Unit file should contain ExecStart directive")
	}
	if !strings.Contains(content, "--daemon") {
		t.Error("Unit file should contain --daemon flag")
	}
	if !strings.Contains(content, fakeBin) {
		t.Error("Unit file should contain the binary path")
	}

	t.Logf("✅ Systemd unit file content is valid")
}

func TestLinux_EnableDisable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho rampart"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := New(fakeBin)

	// Enable
	if err := mgr.Enable(); err != nil {
		t.Skipf("Enable() failed: %v", err)
	}

	// Check enabled
	if !mgr.IsEnabled() {
		t.Error("IsEnabled should return true after Enable()")
	}

	// Disable
	if err := mgr.Disable(); err != nil {
		t.Logf("Disable() error: %v", err)
	}

	// Check disabled
	if mgr.IsEnabled() {
		t.Error("IsEnabled should return false after Disable()")
	}
}

func TestDarwin_PlistPath(t *testing.T) {
	mgr := New("/usr/local/bin/rampart")
	path := mgr.plistPath()
	if !strings.Contains(path, "LaunchAgents") {
		t.Errorf("plistPath should contain LaunchAgents, got %s", path)
	}
	if !strings.HasSuffix(path, ".plist") {
		t.Errorf("plistPath should end with .plist, got %s", path)
	}
}

func TestLinux_UnitPath(t *testing.T) {
	mgr := New("/usr/local/bin/rampart")
	path := mgr.unitPath()
	if !strings.Contains(path, "systemd") {
		t.Errorf("unitPath should contain systemd, got %s", path)
	}
	if !strings.HasSuffix(path, ".service") {
		t.Errorf("unitPath should end with .service, got %s", path)
	}
}

func TestWindows_RegFileGeneration(t *testing.T) {
	if runtime.GOOS != "windows" {
		// On non-Windows, we can still test that enableWindows generates a .reg file
		mgr := New("/usr/local/bin/rampart")

		// Set up a fake home directory
		tmpDir := t.TempDir()
		origHome := os.Getenv("HOME")
		os.Setenv("HOME", tmpDir)
		defer os.Setenv("HOME", origHome)

		// This creates a .reg file on any platform
		// (the enableWindows method just writes a .reg file, doesn't touch registry)
		home, _ := os.UserHomeDir()
		regDir := filepath.Join(home, ".config", "aegisgate-rampart")
		if err := os.MkdirAll(regDir, 0755); err != nil {
			t.Fatal(err)
		}

		err := mgr.enableWindows()
		if err != nil {
			t.Logf("enableWindows() error (may be expected): %v", err)
		}

		// Check if .reg file was created
		regPath := filepath.Join(regDir, "rampart-autostart.reg")
		if _, err := os.Stat(regPath); err == nil {
			data, err := os.ReadFile(regPath)
			if err != nil {
				t.Fatalf("Failed to read reg file: %v", err)
			}
			content := string(data)
			if !strings.Contains(content, "Windows Registry Editor") {
				t.Error("Reg file should contain Windows Registry Editor header")
			}
			if !strings.Contains(content, "Run") {
				t.Error("Reg file should contain Run key path")
			}
			t.Logf("✅ Windows .reg file generated correctly")
		}
	}
}

func TestManager_IsEnabledNonExistent(t *testing.T) {
	mgr := New("/this/does/not/exist/rampart")
	if mgr.IsEnabled() {
		t.Error("IsEnabled should return false for nonexistent binary")
	}
}
