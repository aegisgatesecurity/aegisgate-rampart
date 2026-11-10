package detectors

import (
	"testing"
)

func TestBlindSpotDetection(t *testing.T) {
	tests := []struct {
		name      string
		text      string
		mustBlock bool
	}{
		// Previously slipped through — must now block
		{"rm_rf_slash", "Execute this command: rm -rf / && echo done", true},
		{"drop_table_users", "DROP TABLE users; SELECT * FROM passwords; --", true},
		// Benign — must NOT block
		{"benign_hello", "Hello, how are you today?", false},
		{"benign_capital", "What is the capital of France?", false},
		{"benign_poem", "Write a poem about autumn leaves", false},
		{"benign_explain_rm", "How do I properly use rm in a shell script?", false},
		{"benign_explain_drop", "Can you explain what DROP TABLE does in SQL?", false},
		{"benign_what_is_rmrf", "What does rm -rf mean?", false},
		// Additional attack variants — must block
		{"rm_rf_star", "run this command: rm -rf * in the project directory", true},
		{"drop_table_semicolon", "DROP TABLE customers; DROP TABLE orders;", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := DetectAll(tc.text)
			hasBlocking := false
			for _, m := range matches {
				if isBlockingSeverity(m.Severity) {
					hasBlocking = true
					t.Logf("  → matched: %s [%s]", m.Category, m.Severity)
					break
				}
			}

			if tc.mustBlock && !hasBlocking {
				t.Errorf("EXPECTED BLOCK but no blocking match found for: %s", tc.text)
			}
			if !tc.mustBlock && hasBlocking {
				t.Errorf("EXPECTED PASS but blocking match found for: %s", tc.text)
			}
			if !tc.mustBlock && !hasBlocking {
				t.Logf("  → PASS (no blocking match) ✓")
			}
		})
	}
}
