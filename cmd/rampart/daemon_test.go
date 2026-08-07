// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsRunning_EmptyPIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")
	// Empty file
	if err := os.WriteFile(pidFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	running, pid := IsRunning(pidFile)
	if running {
		t.Error("IsRunning should return false for empty PID file")
	}
	if pid != 0 {
		t.Errorf("pid = %d, want 0", pid)
	}
}

func TestIsRunning_PID1(t *testing.T) {
	// PID 1 (init) always exists on Linux but may not be signalable
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")
	if err := os.WriteFile(pidFile, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	// Just verify it doesn't crash — signal(0) to PID 1 may fail with EPERM
	running, _ := IsRunning(pidFile)
	t.Logf("IsRunning(PID 1) = running=%v", running)
	// Don't assert on the result — it depends on process permissions
}

func TestIsRunning_NegativePID(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")
	if err := os.WriteFile(pidFile, []byte("-1"), 0644); err != nil {
		t.Fatal(err)
	}
	running, _ := IsRunning(pidFile)
	if running {
		t.Error("IsRunning should return false for negative PID")
	}
}

func TestIsRunning_VeryLargePID(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")
	if err := os.WriteFile(pidFile, []byte("999999999"), 0644); err != nil {
		t.Fatal(err)
	}
	running, _ := IsRunning(pidFile)
	// A PID of 999999999 likely doesn't exist
	// Just verify it doesn't crash
	t.Logf("IsRunning(999999999) = running=%v", running)
}

func TestIsRunning_WhitespaceInPID(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")
	if err := os.WriteFile(pidFile, []byte(" 1234 \n"), 0644); err != nil {
		t.Fatal(err)
	}
	running, pid := IsRunning(pidFile)
	// strconv.Atoi should fail on whitespace
	t.Logf("IsRunning(whitespace) = running=%v, pid=%d", running, pid)
	// This should return false because Atoi fails on " 1234 \n"
	if running {
		t.Error("IsRunning should return false for PID with whitespace")
	}
}

func TestDaemon_WritePID_Overwrite(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")

	// Write initial content
	if err := os.WriteFile(pidFile, []byte("12345"), 0644); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{pidFile: pidFile}
	if err := d.writePID(); err != nil {
		t.Fatalf("writePID failed: %v", err)
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("failed to read PID file: %v", err)
	}

	// Should have been overwritten with current PID
	if string(data) == "12345" {
		t.Error("writePID should have overwritten the old PID")
	}
}

func TestGetConfigDir_Environment(t *testing.T) {
	dir := getConfigDir()
	// Should always return a non-empty path
	if dir == "" {
		t.Error("getConfigDir returned empty string")
	}
	// Should contain aegisgate (case-insensitive for Windows: "AegisGate Rampart")
	base := filepath.Base(dir)
	if !strings.Contains(strings.ToLower(base), "aegisgate") {
		t.Errorf("getConfigDir base = %q, should contain 'aegisgate'", base)
	}
}

func TestDaemon_RemovePID_Cleanup(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")

	d := &Daemon{pidFile: pidFile}
	if err := d.writePID(); err != nil {
		t.Fatalf("writePID failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(pidFile); err != nil {
		t.Fatalf("PID file should exist after writePID: %v", err)
	}

	// Remove it
	d.removePID()

	// Verify file is gone
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("PID file should be removed after removePID")
	}

	// Remove again - should be idempotent
	d.removePID()
}
