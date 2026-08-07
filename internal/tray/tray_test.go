// SPDX-License-Identifier: Apache-2.0
package tray

import (
	"bytes"
	"testing"
)

func TestGetDefaultIconBytes(t *testing.T) {
	icon := GetDefaultIconBytes()
	if len(icon) == 0 {
		t.Error("GetDefaultIconBytes returned empty bytes")
	}
	// Verify PNG magic number
	if len(icon) < 8 {
		t.Fatal("icon data too short")
	}
	if icon[0] != 0x89 || icon[1] != 0x50 || icon[2] != 0x4E || icon[3] != 0x47 {
		t.Errorf("icon does not start with PNG magic number, got %x", icon[:4])
	}
}

func TestGetDefaultIconBytes_IsValidPNG(t *testing.T) {
	icon := GetDefaultIconBytes()
	if !bytes.Equal(icon[:4], []byte{0x89, 0x50, 0x4E, 0x47}) {
		t.Error("default icon is not a valid PNG")
	}
	// Check IHDR chunk
	if !bytes.Equal(icon[12:16], []byte("IHDR")) {
		t.Error("PNG IHDR chunk not found at expected offset")
	}
}

func TestNew(t *testing.T) {
	cfg := Config{Port: 8080, Targets: 5}
	tr := New(cfg)
	if tr == nil {
		t.Fatal("New returned nil")
	}
	if tr.port != 8080 {
		t.Errorf("tr.port = %d, want 8080", tr.port)
	}
	if tr.targets != 5 {
		t.Errorf("tr.targets = %d, want 5", tr.targets)
	}
	if tr.running {
		t.Error("new tray should not be running")
	}
	if tr.detectionCount != 0 {
		t.Errorf("tr.detectionCount = %d, want 0", tr.detectionCount)
	}
}

func TestNew_DefaultConfig(t *testing.T) {
	cfg := Config{}
	tr := New(cfg)
	if tr == nil {
		t.Fatal("New returned nil")
	}
	if tr.port != 0 {
		t.Errorf("tr.port = %d, want 0", tr.port)
	}
	if tr.targets != 0 {
		t.Errorf("tr.targets = %d, want 0", tr.targets)
	}
}

func TestIsRunning(t *testing.T) {
	tr := &Tray{}
	if tr.IsRunning() {
		t.Error("default tray should not be running")
	}
	tr.running = true
	if !tr.IsRunning() {
		t.Error("tray with running=true should report running")
	}
}

func TestEnsureRunning(t *testing.T) {
	// Just verify it doesn't panic
	EnsureRunning()
}

func TestNewWithDifferentPorts(t *testing.T) {
	tests := []struct {
		port    int
		targets int
	}{
		{0, 0},
		{8080, 1},
		{9090, 10},
		{443, 100},
	}
	for _, tt := range tests {
		tr := New(Config{Port: tt.port, Targets: tt.targets})
		if tr.port != tt.port {
			t.Errorf("port = %d, want %d", tr.port, tt.port)
		}
		if tr.targets != tt.targets {
			t.Errorf("targets = %d, want %d", tr.targets, tt.targets)
		}
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := Config{Port: 1234, Targets: 7}
	if cfg.Port != 1234 {
		t.Errorf("Port = %d, want 1234", cfg.Port)
	}
	if cfg.Targets != 7 {
		t.Errorf("Targets = %d, want 7", cfg.Targets)
	}
}

func TestTrayStructDefaults(t *testing.T) {
	tr := &Tray{}
	if tr.running {
		t.Error("Tray should default to not running")
	}
	if tr.detectionCount != 0 {
		t.Errorf("detectionCount should default to 0, got %d", tr.detectionCount)
	}
}
