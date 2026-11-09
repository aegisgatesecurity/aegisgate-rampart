// SPDX-License-Identifier: Apache-2.0
// Test coverage for isEducationalFP in pkg/detector

package detector

import "testing"

func TestIsEducationalFP(t *testing.T) {
	tests := []struct {
		name        string
		category    string
		matchedText string
		expect      bool
	}{
		{"evasion category", "evasion", "some text", true},
		{"path-traversal category", "path-traversal", "../etc/passwd", true},
		{"pii-financial category", "pii-financial", "1234567890", true},
		{"pii-us-core category", "pii-us-core", "123-45-6789", true},
		{"pii-us-extended category", "pii-us-extended", "DL1234567", true},
		{"pii-international category", "pii-international", "AB1234567", true},
		{"evasion substring", "evasion_lolbin", "powershell", true},
		{"sensitive_file substring", "sensitive_file_ssh_key", "id_rsa", true},
		{"icd in matched text", "compliance", "ICD-10 code J00", true},
		{"icd in category", "pii_icd10_code", "J00", true},
		{"secrets category not FP", "secrets", "AKIA1234567890ABCD", false},
		{"xss category not FP", "xss", "<script>alert(1)</script>", false},
		{"empty category", "", "some text", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isEducationalFP(tt.category, tt.matchedText)
			if got != tt.expect {
				t.Errorf("isEducationalFP(%q, %q) = %v, want %v", tt.category, tt.matchedText, got, tt.expect)
			}
		})
	}
}
