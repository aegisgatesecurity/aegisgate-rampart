// SPDX-License-Identifier: Apache-2.0
//go:build windows

package main

import (
	"testing"
)

func TestReloadSignal_Windows(t *testing.T) {
	sig := reloadSignal()
	if sig != nil {
		t.Errorf("expected nil reload signal on Windows, got %v", sig)
	}
}

func TestShutdownSignals_Windows(t *testing.T) {
	sigs := shutdownSignals()
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal on Windows, got %d", len(sigs))
	}
	if sigs[0].String() != "interrupt" {
		t.Errorf("expected interrupt signal, got %v", sigs[0])
	}
}
