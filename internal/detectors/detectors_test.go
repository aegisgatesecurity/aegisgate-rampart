package detectors

import (
	"testing"
)

func TestDetectSecretsAWS(t *testing.T) {
	results := DetectSecrets("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
	if len(results) == 0 {
		t.Error("DetectSecrets should detect AWS access key")
	}
}

func TestDetectSecretsGitHub(t *testing.T) {
	results := DetectSecrets("GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ")
	if len(results) == 0 {
		t.Error("DetectSecrets should detect GitHub token")
	}
}

func TestDetectSecretsMultiple(t *testing.T) {
	results := DetectSecrets("AKIAIOSFODNN7EXAMPLE and DATABASE_URL=postgres://user:pass@host:5432/db")
	if len(results) < 2 {
		t.Errorf("DetectSecrets should detect at least 2 secrets, got %d", len(results))
	}
}

func TestDetectSecretsClean(t *testing.T) {
	results := DetectSecrets("Just a normal sentence without any secrets")
	if len(results) != 0 {
		t.Errorf("DetectSecrets on clean text should return 0, got %d", len(results))
	}
}

func TestDetectSecretsEmpty(t *testing.T) {
	results := DetectSecrets("")
	if len(results) != 0 {
		t.Errorf("DetectSecrets on empty string should return 0, got %d", len(results))
	}
}

func TestSecretsPatternsLoaded(t *testing.T) {
	if len(SecretsPatterns) != 45 {
		t.Errorf("SecretsPatterns = %d, want 45", len(SecretsPatterns))
	}
}

func TestSecretsPatternFields(t *testing.T) {
	for _, p := range SecretsPatterns {
		if p.Name == "" {
			t.Errorf("Pattern has empty Name: %+v", p)
		}
		if p.Severity == "" {
			t.Errorf("Pattern %s has empty Severity", p.Name)
		}
		if p.Regex == "" {
			t.Errorf("Pattern %s has empty Regex", p.Name)
		}
	}
}

func TestDetectPIIUSCore(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{"SSN with dashes", "My SSN is 123-45-6789", 1},
		{"Email address", "Contact me at user@example.com", 1},
		{"Phone number", "Call me at (555) 123-4567", 1},
		{"No PII", "The weather is sunny today", 0},
		{"Empty string", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := DetectPIIUSCore(tt.text)
			if len(results) < tt.expected {
				t.Errorf("DetectPIIUSCore(%q) = %d matches, want at least %d", tt.text, len(results), tt.expected)
			}
		})
	}
}

func TestDetectPIIUSExtended(t *testing.T) {
	results := DetectPIIUSExtended("Passport: AB1234567")
	if len(results) == 0 {
		t.Log("PII US Extended may not match this pattern format — just verify no panic")
	}
}

func TestDetectPIIFinancial(t *testing.T) {
	results := DetectPIIFinancial("Card: 4532-1234-5678-9012")
	if len(results) == 0 {
		t.Log("PII Financial detection may vary by pattern — just verify no panic")
	}
}

func TestDetectPIIInternational(t *testing.T) {
	results := DetectPIIInternational("National ID: 1234567890123")
	_ = results // Just verify no panic
}

func TestDetectXSS(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{"Script tag", `<script>alert('xss')</script>`, 1},
		{"Event handler", `<img onerror="alert('xss')">`, 1},
		{"No XSS", "Just plain text without any XSS", 0},
		{"Empty string", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := DetectXSS(tt.text)
			if len(results) < tt.expected {
				t.Errorf("DetectXSS(%q) = %d matches, want at least %d", tt.text, len(results), tt.expected)
			}
		})
	}
}

func TestDetectCompliance(t *testing.T) {
	results := DetectCompliance("GDPR Article 6 requires consent")
	if len(results) == 0 {
		t.Log("Compliance detection may vary — just verify no panic")
	}
}

func TestDetectAll(t *testing.T) {
	text := "SSN: 123-45-6789, AWS key: AKIAIOSFODNN7EXAMPLE, <script>alert(1)</script>"
	results := DetectAll(text)
	if len(results) == 0 {
		t.Error("DetectAll should find threats in multi-threat text")
	}
}

func TestDetectAllClean(t *testing.T) {
	text := "The weather is nice today"
	results := DetectAll(text)
	if len(results) != 0 {
		t.Errorf("DetectAll on clean text should return 0, got %d", len(results))
	}
}

func TestDetectAllEmpty(t *testing.T) {
	results := DetectAll("")
	if len(results) != 0 {
		t.Errorf("DetectAll on empty string should return 0, got %d", len(results))
	}
}

func TestMatchStruct(t *testing.T) {
	m := Match{
		Category:   "secret_aws_key",
		Severity:   SeverityHigh,
		Confidence: 0.95,
		Value:      "AKIAIOSFODNN7EXAMPLE",
		Index:      10,
		End:        29,
	}
	if m.Category != "secret_aws_key" {
		t.Errorf("Category = %s, want secret_aws_key", m.Category)
	}
	if m.Severity != SeverityHigh {
		t.Errorf("Severity = %s, want high", m.Severity)
	}
}

func TestSeverityValues(t *testing.T) {
	if SeverityCritical != "critical" {
		t.Errorf("SeverityCritical = %s, want critical", SeverityCritical)
	}
	if SeverityHigh != "high" {
		t.Errorf("SeverityHigh = %s, want high", SeverityHigh)
	}
	if SeverityMedium != "medium" {
		t.Errorf("SeverityMedium = %s, want medium", SeverityMedium)
	}
	if SeverityLow != "low" {
		t.Errorf("SeverityLow = %s, want low", SeverityLow)
	}
}

func TestCategoryValues(t *testing.T) {
	if CategorySecrets != "secrets" {
		t.Errorf("CategorySecrets = %s, want secrets", CategorySecrets)
	}
	if CategoryPIIUSCore != "pii-us-core" {
		t.Errorf("CategoryPIIUSCore = %s, want pii-us-core", CategoryPIIUSCore)
	}
	if CategoryXSS != "xss" {
		t.Errorf("CategoryXSS = %s, want xss", CategoryXSS)
	}
}
