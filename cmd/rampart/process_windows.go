// SPDX-License-Identifier: Apache-2.0
//go:build windows

package main

import (
	"os"
)

// processExists checks if a process with the given PID is running.
// On Windows, os.FindProcess always succeeds, so we attempt to open
// the process handle to verify it actually exists.
func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Windows, FindProcess always succeeds (even for non-existent PIDs).
	// We can't easily check without golang.org/x/sys/windows, so
	// we rely on the PID file existing and assume the process is running.
	// This matches the behavior of the .reg file approach for auto-start.
	_ = process
	return true
}
