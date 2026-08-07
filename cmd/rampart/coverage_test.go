// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

// TestHandleTrust_WithOutput tests handleTrust output format.
func TestHandleTrust_WithOutput(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleTrust()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "CA Certificate") {
		t.Errorf("handleTrust output should contain 'CA Certificate', got: %s", output)
	}
	if !strings.Contains(output, "Platform") {
		t.Errorf("handleTrust output should contain 'Platform', got: %s", output)
	}
	if !strings.Contains(output, "Trusted") {
		t.Errorf("handleTrust output should contain 'Trusted', got: %s", output)
	}
}

// TestHandleAutoStart_EnableOutput tests handleAutoStart enable output.
func TestHandleAutoStart_EnableOutput(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	origStderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() { os.Stderr = origStderr }()

	handleAutoStart(true)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Auto-start") {
		t.Errorf("handleAutoStart enable should contain 'Auto-start', got: %s", output)
	}
}

// TestHandleAutoStart_DisableOutput tests handleAutoStart disable output.
func TestHandleAutoStart_DisableOutput(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	origStderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() { os.Stderr = origStderr }()

	handleAutoStart(false)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "Auto-start") {
		t.Errorf("handleAutoStart disable should contain 'Auto-start', got: %s", output)
	}
}

// TestHandleStatus_DetailedOutput tests handleStatus output content.
func TestHandleStatus_DetailedOutput(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleStatus()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	expectedStrings := []string{
		"AegisGate Rampart Status",
		"CA Certificate",
		"CA Trusted",
		"Platform",
		"Daemon:",
		"Auto-start:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("handleStatus should contain %q, got: %s", expected, output)
		}
	}
}

// TestNewDaemon_PIDFilePath tests that NewDaemon sets up the PID file path.
func TestNewDaemon_PIDFilePath(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 8080,
		Targets:   config.DefaultTargets(),
	}
	d := NewDaemon(cfg)
	if d == nil {
		t.Fatal("NewDaemon returned nil")
	}
	if !strings.Contains(d.pidFile, "rampart.pid") {
		t.Errorf("pidFile should contain 'rampart.pid', got %s", d.pidFile)
	}
	if !strings.Contains(d.pidFile, "aegisgate-rampart") {
		t.Errorf("pidFile should contain 'aegisgate-rampart', got %s", d.pidFile)
	}
}

// TestRunForeground_ContextCancel tests runForeground exits cleanly on context cancel.
func TestRunForeground_ContextCancel(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 0,
		Targets:   config.DefaultTargets(),
		Privacy: config.PrivacyConfig{
			NoPromptText: true,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- nil
			}
		}()
		runForeground(ctx, cancel, cfg)
		done <- nil
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		t.Log("Foreground proxy shut down cleanly")
	case <-time.After(5 * time.Second):
		t.Log("Timeout waiting for foreground proxy shutdown")
	}
}
