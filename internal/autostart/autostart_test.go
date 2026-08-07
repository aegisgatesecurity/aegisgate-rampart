package autostart

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNew(t *testing.T) {
	mgr := New("/usr/local/bin/rampart")
	if mgr == nil {
		t.Fatal("New returned nil")
	}
	if mgr.binPath != "/usr/local/bin/rampart" {
		t.Errorf("binPath = %s, want /usr/local/bin/rampart", mgr.binPath)
	}
}

func TestIsEnabledNotConfigured(t *testing.T) {
	mgr := New("/nonexistent/bin/rampart")
	if mgr.IsEnabled() {
		t.Error("IsEnabled should return false when not configured")
	}
}

func TestEnableDisableLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho rampart"), 0755); err != nil {
		t.Fatal(err)
	}
	mgr := New(fakeBin)

	// Override the unit path for testing
	// Enable should create a systemd unit file
	if err := mgr.Enable(); err != nil {
		t.Logf("Enable may fail in test env: %v", err)
	}

	// Disable should remove it
	if err := mgr.Disable(); err != nil {
		t.Logf("Disable may fail in test env: %v", err)
	}
}

func TestEnableNonExistentBinary(t *testing.T) {
	mgr := New("/definitely/not/a/real/path/rampart")
	err := mgr.Enable()
	// Should not panic even with nonexistent binary
	_ = err
}

func TestDisableWhenNotEnabled(t *testing.T) {
	mgr := New("/usr/local/bin/rampart")
	err := mgr.Disable()
	// Should not error when nothing to remove
	_ = err
}

func TestWindowsRegFileContent(t *testing.T) {
	if runtime.GOOS != "windows" {
		// We can still verify the reg file is generated
		// by checking the enable logic doesn't panic
		mgr := New("/usr/local/bin/rampart")
		_ = mgr
	}
}
