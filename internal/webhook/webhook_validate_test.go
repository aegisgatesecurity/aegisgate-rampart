// SPDX-License-Identifier: Apache-2.0
// Test coverage for webhook validateWebhookURL and enterprise loadConfig

package webhook

import "testing"

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"empty URL", "", true},
		{"valid https", "https://hooks.example.com/webhook", false},
		{"valid http", "http://localhost:8080/webhook", false},
		{"unsupported scheme", "ftp://example.com/webhook", true},
		{"file scheme", "file:///etc/passwd", true},
		{"no host", "https:///webhook", true},
		{"javascript scheme", "javascript:alert(1)", true},
		{"valid with path", "https://example.com/api/v1/webhook", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateWebhookURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}
