// SPDX-License-Identifier: Apache-2.0
//go:build !windows

package main

import (
	"os"
	"syscall"
	"testing"
)

func TestReloadSignal_Unix(t *testing.T) {
	sig := reloadSignal()
	if sig != syscall.SIGHUP {
		t.Errorf("expected SIGHUP, got %v", sig)
	}
}

func TestShutdownSignals_Unix(t *testing.T) {
	sigs := shutdownSignals()
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(sigs))
	}

	hasSIGINT := false
	hasSIGTERM := false
	for _, s := range sigs {
		if s == syscall.SIGINT {
			hasSIGINT = true
		}
		if s == syscall.SIGTERM {
			hasSIGTERM = true
		}
	}
	if !hasSIGINT {
		t.Error("SIGINT missing from shutdown signals")
	}
	if !hasSIGTERM {
		t.Error("SIGTERM missing from shutdown signals")
	}
}

func TestReloadSignalIsOsSignal(t *testing.T) {
	sig := reloadSignal()
	// Verify it implements os.Signal
	var _ os.Signal = sig //nolint:staticcheck // QF1011: explicit type for documentation
}
