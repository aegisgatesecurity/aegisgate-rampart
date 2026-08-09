// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Exported Test Helpers for Cross-Product Integration
// =========================================================================
//
// This file exports internal proxy methods for use by integration tests
// in external packages (e.g., tests/integration/).
//
// =========================================================================

package proxy

import "github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"

// ScanForTest runs detection on the given body and returns the summary.
// This is an exported wrapper around scanAndAlert for integration tests.
// It also triggers notification, audit logging, and platform forwarding
// just like the real proxy would.
func (p *Proxy) ScanForTest(direction, host, path string, body []byte) *detector.Summary {
	return p.scanAndAlert(direction, host, path, body)
}
