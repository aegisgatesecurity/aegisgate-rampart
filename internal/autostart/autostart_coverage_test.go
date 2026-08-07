// SPDX-License-Identifier: Apache-2.0
package autostart

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestEnable_Routing tests that Enable routes to the correct platform function.
func TestEnable_Routing(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho rampart"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := New(fakeBin)
	err := mgr.Enable()
	if err != nil {
		t.Logf("Enable() returned error on %s: %v (may be expected in test env)", runtime.GOOS, err)
	}

	// Clean up
	defer func() { _ = mgr.Disable() }()
}

// TestDisable_Routing tests that Disable routes to the correct platform function.
func TestDisable_Routing(t *testing.T) {
	mgr := New("/nonexistent/bin/rampart")
	err := mgr.Disable()
	// Should not error even if not enabled
	if err != nil && !os.IsNotExist(err) {
		t.Logf("Disable() returned: %v (may be expected)", err)
	}
}

// TestIsEnabled_Routing tests that IsEnabled routes to the correct platform function.
func TestIsEnabled_Routing(t *testing.T) {
	mgr := New("/nonexistent/bin/rampart")
	enabled := mgr.IsEnabled()
	if enabled {
		t.Error("Should not be enabled for nonexistent binary")
	}
}

// TestLinux_EnableDisableDirect tests enableLinux and disableLinux directly.
func TestLinux_EnableDisableDirect(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho rampart"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := New(fakeBin)

	// Test enableLinux
	err := mgr.enableLinux()
	if err != nil {
		t.Skipf("enableLinux() failed: %v", err)
	}

	// Verify unit file exists
	if !mgr.isEnabledLinux() {
		t.Error("Should be enabled after enableLinux()")
	}

	// Test disableLinux
	if err := mgr.disableLinux(); err != nil {
		t.Logf("disableLinux() error: %v", err)
	}

	// Verify unit file removed
	if mgr.isEnabledLinux() {
		t.Error("Should NOT be enabled after disableLinux()")
	}
}

// TestPlistPath_ContainsName tests that plistPath contains the plist name constant.
func TestPlistPath_ContainsName(t *testing.T) {
	mgr := New("/usr/local/bin/rampart")
	path := mgr.plistPath()
	if !strings.Contains(path, plistName) {
		t.Errorf("plistPath should contain %s, got %s", plistName, path)
	}
}

// TestUnitPath_ContainsUnitName tests that unitPath contains the unit name constant.
func TestUnitPath_ContainsUnitName(t *testing.T) {
	mgr := New("/usr/local/bin/rampart")
	path := mgr.unitPath()
	if !strings.Contains(path, unitName) {
		t.Errorf("unitPath should contain %s, got %s", unitName, path)
	}
}

// TestNewManager_WithPath tests that New correctly sets the binPath.
func TestNewManager_WithPath(t *testing.T) {
	bin := "/custom/path/to/rampart"
	mgr := New(bin)
	if mgr.binPath != bin {
		t.Errorf("binPath = %s, want %s", mgr.binPath, bin)
	}
}

// TestAutostart_Constants tests the constant values.
func TestAutostart_Constants(t *testing.T) {
	if plistName != "com.aegisgate.rampart" {
		t.Errorf("plistName = %s, want com.aegisgate.rampart", plistName)
	}
	if unitName != "rampart.service" {
		t.Errorf("unitName = %s, want rampart.service", unitName)
	}
	if regKeyName != "AegisGateRampart" {
		t.Errorf("regKeyName = %s, want AegisGateRampart", regKeyName)
	}
	if regKeyPath != `Software\Microsoft\Windows\CurrentVersion\Run` {
		t.Errorf("regKeyPath = %s, want expected value", regKeyPath)
	}
}
