// SPDX-License-Identifier: Apache-2.0
// Test coverage for isEducationalExemptPattern and related proxy helpers

package proxy

import (
	"testing"
)

func TestIsEducationalExemptPattern(t *testing.T) {
	// Patterns that ARE exempt
	exemptPatterns := []string{
		"evasion_lolbin",
		"sensitive_file_ssh_key",
		"sensitive_file_env",
		"sensitive_file_aws_creds",
		"sensitive_file_hosts",
		"pii_icd10_patient_ctx",
		"pii_icd10_code",
		"pii_letter_only_id",
		"toxicity_self_harm",
		"toxicity_sexual",
		"toxicity",
		"ml_threat",
		"char_cnn_bilstm",
		"harmful_hacking_instructions",
		"harmful_violence_instructions",
	}
	for _, p := range exemptPatterns {
		t.Run("exempt_"+p, func(t *testing.T) {
			if !isEducationalExemptPattern(p) {
				t.Errorf("isEducationalExemptPattern(%q) = false, want true", p)
			}
		})
	}

	// Patterns that are NOT exempt
	nonExemptPatterns := []string{
		"secret_aws_key",
		"pii_ssn",
		"xss_script_tag",
		"sqli_union_select",
		"",
		"unknown_pattern",
		"prompt_injection",
	}
	for _, p := range nonExemptPatterns {
		t.Run("not_exempt_"+p, func(t *testing.T) {
			if isEducationalExemptPattern(p) {
				t.Errorf("isEducationalExemptPattern(%q) = true, want false", p)
			}
		})
	}
}
