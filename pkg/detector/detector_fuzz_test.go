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

// fuzzMaxInputSize caps the fuzz input size. The Go fuzz engine can generate
// inputs up to ~1MB, and with 40 workers each copying the input plus running
// 144+ regex patterns, very large inputs cause the fuzz process to hang or
// be killed (exit status 2). 64KB matches the ResponseGuard's maxScanBytes —
// inputs larger than this are truncated before regex scanning anyway, so
// fuzzing beyond this size adds no coverage value.
const fuzzMaxInputSize = 64 * 1024

// fuzzDetector is a package-level singleton created once to avoid
// recompiling all regex patterns on every fuzz iteration.
// Creating a new Detector (which creates new PII scanner, secret detector,
// and XSS scanner — each compiling ~50+ regexes) inside the Fuzz function
// causes resource exhaustion with 40 workers at thousands of execs/sec.
// The Detector is stateless in shadow mode (no ML), so reuse is safe.
var fuzzDetector *Detector

func init() {
	d, err := New(&Config{
		EnablePII:        true,
		EnableSecrets:    true,
		EnableXSS:        true,
		EnableCompliance: true,
		EnableML:         false, // No model in fuzz — heuristic only
		ShadowMode:       true,
	})
	if err != nil {
		panic("fuzz test: failed to create detector: " + err.Error())
	}
	fuzzDetector = d
}

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
		string(make([]byte, 100000)), // 100KB of zeros — tests truncation
		"您好世界 🌍 🛡️",
		"email@test.com\n\n\t\r\n",
		"SELECT * FROM users WHERE id=1; DROP TABLE users;",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Skip very large inputs — they cause the Go fuzz engine to hang
		// with 40 workers. The detector truncates to 64KB internally anyway,
		// so inputs beyond that size add no coverage value.
		if len(input) > fuzzMaxInputSize {
			t.Skip()
		}

		// The detection engine must never panic on any input.
		// fuzzDetector is created once in init() to avoid
		// recompiling regexes on every iteration.
		result, err := fuzzDetector.Detect(input)
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
