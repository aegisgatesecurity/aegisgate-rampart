// SPDX-License-Identifier: Apache-2.0
// Provenance: Minimal shim replacing github.com/aegisgatesecurity/aegisgate-platform/pkg/logging
// Version: v4.0.0 (2026-08-05)
// Modifications: Stripped to bare minimum — Severity types and no-op Record for air-gap mode.
// Rampart logs to terminal (TUI) or system notifications (daemon), not structured ring buffer.

package logging

import (
	"fmt"
	"os"
	"time"
)

// Severity represents event severity level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Event represents a security or log event.
// Subset of Platform's logging.Event — only fields used by Rampart's response guard.
type Event struct {
	Time      time.Time `json:"time,omitempty"`
	Type      string    `json:"type"`
	Severity  Severity  `json:"severity"`
	Message   string    `json:"message"`
	ThreatType string   `json:"threatType,omitempty"`
	Pattern   string    `json:"pattern,omitempty"`
}

// Record logs an event. In Rampart's air-gap mode, this writes to stderr.
// When Platform telemetry is connected, this is overridden by pkg/telemetry.
func Record(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	// Simple stderr logging — Rampart's TUI will have its own display
	fmt.Fprintf(os.Stderr, "[%s] %s: %s\n", e.Severity, e.Type, e.Message)
}