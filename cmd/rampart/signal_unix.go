// SPDX-License-Identifier: Apache-2.0
//go:build !windows

package main

import (
	"os"
	"syscall"
)

// shutdownSignals returns the OS signals that should trigger a graceful shutdown.
// On Unix systems (Linux, macOS), both SIGINT and SIGTERM are supported.
func shutdownSignals() []os.Signal {
	return []os.Signal{syscall.SIGINT, syscall.SIGTERM}
}

// reloadSignal returns the OS signal that triggers configuration hot-reload.
// On Unix systems, SIGHUP is used for reload.
func reloadSignal() os.Signal {
	return syscall.SIGHUP
}
