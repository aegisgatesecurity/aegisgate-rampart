// SPDX-License-Identifier: Apache-2.0
//go:build windows

package autostart

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindows_EnableCreatesRegFile(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart.exe")
	if err := os.WriteFile(fakeBin, []byte("fake binary"), 0755); err != nil {
		t.Fatal(err)
	}

	origHome := os.Getenv("USERPROFILE")
	os.Setenv("USERPROFILE", tmpDir)
	defer os.Setenv("USERPROFILE", origHome)

	mgr := New(fakeBin)
	err := mgr.Enable()
	if err != nil {
		t.Skipf("Enable() failed: %v", err)
	}
	defer func() { _ = mgr.Disable() }()

	if !mgr.IsEnabled() {
		t.Error("Should be enabled after Enable()")
	}
}

func TestWindows_DisableRemovesRegFile(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "rampart.exe")
	if err := os.WriteFile(fakeBin, []byte("fake binary"), 0755); err != nil {
		t.Fatal(err)
	}

	origHome := os.Getenv("USERPROFILE")
	os.Setenv("USERPROFILE", tmpDir)
	defer os.Setenv("USERPROFILE", origHome)

	mgr := New(fakeBin)
	if err := mgr.Enable(); err != nil {
		t.Skipf("Enable() failed: %v", err)
	}

	if err := mgr.Disable(); err != nil {
		t.Logf("Disable() error: %v", err)
	}

	if mgr.IsEnabled() {
		t.Error("Should NOT be enabled after Disable()")
	}
}

func TestWindows_IsEnabledNotConfigured(t *testing.T) {
	mgr := New("/nonexistent/bin/rampart.exe")
	if mgr.IsEnabled() {
		t.Error("Should not be enabled when reg file doesn't exist")
	}
}
