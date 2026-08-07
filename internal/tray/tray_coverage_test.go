// SPDX-License-Identifier: Apache-2.0
package tray

import (
	"testing"
)

// TestConfig_PortAndTargets tests Config fields.
func TestConfig_PortAndTargets(t *testing.T) {
	cfg := Config{Port: 8080, Targets: 27}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.Targets != 27 {
		t.Errorf("Targets = %d, want 27", cfg.Targets)
	}
}

// TestConfig_ZeroValues tests Config zero values.
func TestConfig_ZeroValues(t *testing.T) {
	cfg := Config{}
	if cfg.Port != 0 {
		t.Errorf("Port = %d, want 0", cfg.Port)
	}
	if cfg.Targets != 0 {
		t.Errorf("Targets = %d, want 0", cfg.Targets)
	}
}

// TestNew_WithPort tests New with specific port.
func TestNew_WithPort(t *testing.T) {
	tr := New(Config{Port: 9090, Targets: 5})
	if tr.port != 9090 {
		t.Errorf("port = %d, want 9090", tr.port)
	}
	if tr.targets != 5 {
		t.Errorf("targets = %d, want 5", tr.targets)
	}
}

// TestTray_Defaults tests Tray default values.
func TestTray_Defaults(t *testing.T) {
	tr := &Tray{}
	if tr.running {
		t.Error("Tray should default to not running")
	}
	if tr.detectionCount != 0 {
		t.Errorf("detectionCount should default to 0, got %d", tr.detectionCount)
	}
}

// TestTray_DetectionCount tests detection count manipulation.
func TestTray_DetectionCount(t *testing.T) {
	tr := &Tray{}

	// Test direct detection count update (without calling UpdateDetections
	// which requires menu items)
	tr.detectionCount = 5
	if tr.detectionCount != 5 {
		t.Errorf("detectionCount = %d, want 5", tr.detectionCount)
	}

	// Increment
	tr.detectionCount++
	if tr.detectionCount != 6 {
		t.Errorf("detectionCount = %d, want 6", tr.detectionCount)
	}
}

// TestTray_RunningState tests running state manipulation.
func TestTray_RunningState(t *testing.T) {
	tr := &Tray{}

	if tr.IsRunning() {
		t.Error("Should not be running initially")
	}

	// Set running state directly (without calling SetRunning which needs menu items)
	tr.running = true
	if !tr.IsRunning() {
		t.Error("Should be running after setting running=true")
	}

	tr.running = false
	if tr.IsRunning() {
		t.Error("Should not be running after setting running=false")
	}
}

// TestGetDefaultIconBytes_IsPNG tests that the embedded icon is a valid PNG.
func TestGetDefaultIconBytes_IsPNG(t *testing.T) {
	icon := GetDefaultIconBytes()
	if len(icon) == 0 {
		t.Fatal("GetDefaultIconBytes returned empty bytes")
	}
	if icon[0] != 0x89 || icon[1] != 0x50 || icon[2] != 0x4E || icon[3] != 0x47 {
		t.Errorf("Icon does not start with PNG magic number, got %x", icon[:4])
	}
}

// TestEnsureRunning_NoOp tests that EnsureRunning is a no-op.
func TestEnsureRunning_NoOp(t *testing.T) {
	EnsureRunning() // Should not panic
}

// TestTray_StructFields tests Tray struct field defaults.
func TestTray_StructFields(t *testing.T) {
	tr := &Tray{
		port:           8080,
		targets:        27,
		detectionCount: 0,
		running:        false,
	}

	if tr.port != 8080 {
		t.Errorf("port = %d, want 8080", tr.port)
	}
	if tr.targets != 27 {
		t.Errorf("targets = %d, want 27", tr.targets)
	}
	if tr.detectionCount != 0 {
		t.Errorf("detectionCount = %d, want 0", tr.detectionCount)
	}
	if tr.running {
		t.Error("running should be false")
	}
}
