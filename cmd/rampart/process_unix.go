// SPDX-License-Identifier: Apache-2.0
//go:build !windows

package main

import (
	"os"
	"syscall"
)

// processExists checks if a process with the given PID is running.
// On Unix systems, uses signal 0 to check without sending a signal.
func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}
