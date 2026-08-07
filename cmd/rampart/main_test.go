// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

func TestGetConfigDir(t *testing.T) {
	dir := getConfigDir()
	if dir == "" {
		t.Error("getConfigDir returned empty string")
	}
	home, err := os.UserHomeDir()
	if err == nil {
		expected := filepath.Join(home, ".config", "aegisgate-rampart")
		if dir != expected {
			t.Errorf("getConfigDir = %q, want %q", dir, expected)
		}
	}
}

func TestIsRunning_NoPIDFile(t *testing.T) {
	running, pid := IsRunning("/tmp/nonexistent-rampart-test.pid")
	if running {
		t.Error("IsRunning should return false for nonexistent PID file")
	}
	if pid != 0 {
		t.Errorf("IsRunning pid = %d, want 0", pid)
	}
}

func TestIsRunning_InvalidPID(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")
	err := os.WriteFile(pidFile, []byte("not-a-number"), 0644)
	if err != nil {
		t.Fatalf("failed to write PID file: %v", err)
	}

	running, pid := IsRunning(pidFile)
	if running {
		t.Error("IsRunning should return false for invalid PID content")
	}
	if pid != 0 {
		t.Errorf("IsRunning pid = %d, want 0", pid)
	}
}

func TestIsRunning_DeadProcess(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")
	// Use a PID that almost certainly doesn't exist (very high number)
	err := os.WriteFile(pidFile, []byte("999999999"), 0644)
	if err != nil {
		t.Fatalf("failed to write PID file: %v", err)
	}

	running, _ := IsRunning(pidFile)
	if running {
		t.Error("IsRunning should return false for non-existent process")
	}
}

func TestIsRunning_CurrentProcess(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")
	err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
	if err != nil {
		t.Fatalf("failed to write PID file: %v", err)
	}

	running, pid := IsRunning(pidFile)
	if !running {
		t.Error("IsRunning should return true for current process")
	}
	if pid != os.Getpid() {
		t.Errorf("IsRunning pid = %d, want %d", pid, os.Getpid())
	}
}

func TestDaemon_WritePIDAndRemove(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "rampart.pid")

	d := &Daemon{
		pidFile: pidFile,
	}

	// Test writePID
	if err := d.writePID(); err != nil {
		t.Fatalf("writePID failed: %v", err)
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("failed to read PID file: %v", err)
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatalf("PID file contains invalid content: %q", string(data))
	}
	if pid != os.Getpid() {
		t.Errorf("PID = %d, want %d", pid, os.Getpid())
	}

	// Test removePID
	d.removePID()
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("removePID did not remove PID file")
	}
}

func TestDaemon_WritePID_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "subdir", "rampart.pid")

	d := &Daemon{
		pidFile: pidFile,
	}

	if err := d.writePID(); err != nil {
		t.Fatalf("writePID failed: %v", err)
	}

	if _, err := os.Stat(pidFile); err != nil {
		t.Errorf("PID file not created: %v", err)
	}

	d.removePID()
}

func TestDaemon_RemovePID_Idempotent(t *testing.T) {
	d := &Daemon{
		pidFile: "/tmp/nonexistent-rampart-test-remove.pid",
	}
	// Should not error on nonexistent file
	d.removePID()
}

func TestNewDaemon(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 9999,
		Targets:   config.DefaultTargets(),
	}
	d := NewDaemon(cfg)
	if d == nil {
		t.Fatal("NewDaemon returned nil")
	}
	if d.cfg != cfg {
		t.Error("NewDaemon did not set cfg")
	}
	if d.notify == nil {
		t.Error("NewDaemon did not set notify")
	}
	if d.tray == nil {
		t.Error("NewDaemon did not set tray")
	}
	if d.pidFile == "" {
		t.Error("NewDaemon did not set pidFile")
	}
}
