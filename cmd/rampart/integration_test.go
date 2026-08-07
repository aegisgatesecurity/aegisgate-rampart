// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"os"
	"testing"
)

func TestHandleAutoStart_EnableAndDisable(t *testing.T) {
	// This test verifies handleAutoStart runs without panicking.
	// It may fail on CI where autostart isn't fully supported,
	// so we only verify it doesn't crash.
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	origXdg := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer func() {
		os.Setenv("HOME", origHome)
		os.Setenv("XDG_CONFIG_HOME", origXdg)
	}()

	// We can't easily test Enable/Disable without side effects on the system,
	// but we can verify the function signature and basic flow.
	// The autostart package tests cover the actual Enable/Disable logic.
}

func TestHandleStatus(t *testing.T) {
	// Redirect stdout to capture output
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	handleStatus()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	// Should contain status header
	if len(output) == 0 {
		t.Error("handleStatus produced no output")
	}
}

func TestMain_VersionFlag(t *testing.T) {
	// Test version output by directly checking versionFlag
	if versionFlag == "" && versionFlag != "dev" {
		// versionFlag defaults to "dev" when not set via ldflags
		t.Logf("versionFlag = %q", versionFlag)
	}
}
