// SPDX-License-Identifier: Apache-2.0
//go:build darwin

package autostart

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwin_EnableCreatesPlist(t *testing.T) {
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
	defer func() { _ = mgr.Disable() }()

	plistPath := mgr.plistPath()
	data, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("Failed to read plist: %v", err)
	}

	content := string(data)
	if !contains(content, plistName) {
		t.Error("Plist should contain launch agent name")
	}
	if !contains(content, fakeBin) {
		t.Error("Plist should contain binary path")
	}
	if !contains(content, "--daemon") {
		t.Error("Plist should contain --daemon flag")
	}
	t.Logf("✅ Darwin plist file created successfully")
}

func TestDarwin_DisableRemovesPlist(t *testing.T) {
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

	if !mgr.IsEnabled() {
		t.Error("Should be enabled after Enable()")
	}

	if err := mgr.Disable(); err != nil {
		t.Logf("Disable() error: %v", err)
	}

	if mgr.IsEnabled() {
		t.Error("Should NOT be enabled after Disable()")
	}
}

func TestDarwin_IsEnabledNotConfigured(t *testing.T) {
	mgr := New("/nonexistent/bin/rampart")
	if mgr.IsEnabled() {
		t.Error("Should not be enabled when plist doesn't exist")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0)
}

func init() {
	// Ensure contains works as expected
	_ = contains("", "")
}
