// SPDX-License-Identifier: Apache-2.0
//go:build windows

package main

import (
	"os"
)

// shutdownSignals returns the OS signals that should trigger a graceful shutdown.
// On Windows, only SIGINT is supported (SIGTERM does not exist).
func shutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

// reloadSignal returns the signal that triggers configuration hot-reload.
// Windows doesn't have SIGHUP; reload must be triggered via the API.
func reloadSignal() os.Signal {
	return nil // No SIGHUP on Windows
}
