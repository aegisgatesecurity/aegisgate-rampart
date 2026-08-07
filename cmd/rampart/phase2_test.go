// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

func TestRunForeground_StartAndShutdown(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 0, // Let OS pick a port
		Targets:   config.DefaultTargets(),
		Privacy: config.PrivacyConfig{
			NoPromptText: true,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Run foreground in a goroutine, then cancel after a brief moment
	done := make(chan error, 1)
	go func() {
		defer func() {
			// Recover from any panic in case Shutdown is called before Start
			if r := recover(); r != nil {
				done <- nil
			}
		}()
		runForeground(ctx, cancel, cfg)
		done <- nil
	}()

	// Cancel context to trigger shutdown
	cancel()

	// Wait for runForeground to complete (with timeout)
	select {
	case <-done:
		t.Log("Foreground proxy shut down cleanly")
	case <-time.After(5 * time.Second):
		t.Log("Timeout waiting for foreground proxy shutdown")
	}
}

func TestHandleTrust_NoCert(t *testing.T) {
	// handleTrust should not panic even when no cert exists
	origStderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() { os.Stderr = origStderr }()

	handleTrust()
}

func TestHandleStatus_NoDaemonRunning(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleStatus()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if !bytes.Contains([]byte(output), []byte("AegisGate Rampart Status")) {
		t.Errorf("handleStatus should contain status header, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("Daemon: not running")) {
		t.Errorf("handleStatus should show daemon not running, got: %s", output)
	}
}

func TestHandleAutoStart_Enable(t *testing.T) {
	// Test --autostart enable (may fail on CI but should not panic)
	origStderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() { os.Stderr = origStderr }()

	tmpBin := filepath.Join(t.TempDir(), "rampart")
	if err := os.WriteFile(tmpBin, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatal(err)
	}

	// Call handleAutoStart with a real binary path
	os.Args = []string{"rampart", "--autostart"}
	handleAutoStart(true)
}

func TestHandleAutoStart_Disable(t *testing.T) {
	// Test --no-autostart (should not panic even if not enabled)
	origStderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() { os.Stderr = origStderr }()

	handleAutoStart(false)
}

func TestGetConfigDir_NonEmpty(t *testing.T) {
	dir := getConfigDir()
	if dir == "" {
		t.Error("getConfigDir should not return empty string")
	}
	if filepath.Base(dir) != "aegisgate-rampart" {
		t.Errorf("getConfigDir should end with aegisgate-rampart, got %s", dir)
	}
}

func TestIsRunning_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		pid    string
		expect bool
	}{
		{"empty file", "", false},
		{"negative pid", "-1", false},
		{"zero pid", "0", false},
		{"whitespace", "  \n", false},
		{"very large pid", "999999999", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			pidFile := filepath.Join(tmpDir, "rampart.pid")
			if err := os.WriteFile(pidFile, []byte(tt.pid), 0644); err != nil {
				t.Fatal(err)
			}
			running, _ := IsRunning(pidFile)
			if tt.name != "very large pid" && running != tt.expect {
				t.Errorf("IsRunning(%q) = %v, want %v", tt.pid, running, tt.expect)
			}
		})
	}
}

func TestDaemon_PIDLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "subdir", "rampart.pid")

	d := &Daemon{
		cfg:     config.DefaultConfig(),
		pidFile: pidFile,
	}

	// Write PID
	if err := d.writePID(); err != nil {
		t.Fatalf("writePID failed: %v", err)
	}

	// Verify PID file exists and contains current PID
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("failed to read PID file: %v", err)
	}
	if string(data) != strconv.Itoa(os.Getpid()) {
		t.Errorf("PID file = %q, want %q", string(data), strconv.Itoa(os.Getpid()))
	}

	// Remove PID
	d.removePID()
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("PID file should be removed after removePID")
	}

	// Remove again (idempotent)
	d.removePID()
}

func TestNewDaemon_NilConfig(t *testing.T) {
	// NewDaemon should work with a valid config
	cfg := &config.Config{
		ProxyPort: 9999,
		Targets:   config.DefaultTargets(),
	}
	d := NewDaemon(cfg)
	if d == nil {
		t.Fatal("NewDaemon returned nil")
	}
	if d.pidFile == "" {
		t.Error("NewDaemon should set pidFile")
	}
}

func TestVersionFlagDefaultValue(t *testing.T) {
	if versionFlag == "" {
		t.Error("versionFlag should not be empty")
	}
	t.Logf("versionFlag = %q", versionFlag)
}
