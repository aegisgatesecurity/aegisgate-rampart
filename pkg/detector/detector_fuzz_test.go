// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — Detection Fuzz Targets
// =========================================================================
//
// Fuzz the detection engine with random input to find panics and crashes.
// Run: go test -fuzz=FuzzScanRequest -fuzztime=60s ./pkg/detector/
//
// =========================================================================

package detector

import (
	"testing"
)

// FuzzScanRequest fuzzes the detection pipeline with arbitrary text input.
// This tests PII scanning, secret detection, XSS, and compliance detection
// with random, adversarial, and edge-case inputs.
func FuzzScanRequest(f *testing.F) {
	// Seed corpus: clean text, PII, secrets, XSS, unicode, edge cases
	seeds := []string{
		"Hello, how are you?",
		"My SSN is 123-45-6789",
		"AWS key: AKIAIOSFODNN7EXAMPLE",
		"<script>alert('xss')</script>",
		"Credit card: 4532-1234-5678-9012",
		"",
		" ",
		"\x00\x01\x02",
		string(make([]byte, 100000)), // 100KB of zeros
		"您好世界 🌍 🛡️",
		"email@test.com\n\n\t\r\n",
		"SELECT * FROM users WHERE id=1; DROP TABLE users;",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		det, err := New(&Config{
			EnablePII:        true,
			EnableSecrets:    true,
			EnableXSS:        true,
			EnableCompliance: true,
			EnableML:         false, // No model in fuzz — heuristic only
			ShadowMode:       true,
		})
		if err != nil {
			t.Fatal("Failed to create detector:", err)
		}

		// The detection engine must never panic on any input
		result, err := det.Detect(input)
		if err != nil {
			// Errors are acceptable (e.g., empty input), panics are not
			return
		}

		// Basic sanity: result should not be nil
		if result == nil {
			t.Error("Detect() returned nil result without error")
		}
	})
}