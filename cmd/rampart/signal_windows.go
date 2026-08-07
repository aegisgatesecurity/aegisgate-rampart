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
