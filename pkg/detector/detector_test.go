package detector

import (
	"testing"
)

func TestDetectorNew(t *testing.T) {
	cfg := DefaultConfig()
	// Disable ML for test (no model file available)
	cfg.EnableML = false

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if d == nil {
		t.Fatal("New() returned nil detector")
	}
	if d.guard == nil {
		t.Fatal("guard should not be nil")
	}
}

func TestDetectPII(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test SSN detection
	result, err := d.Detect("My SSN is 123-45-6789")
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}
	if result == nil {
		t.Fatal("Detect() returned nil result")
	}

	foundPII := false
	for _, r := range result.Results {
		if r.Category == "pii" || r.Category == "pii-us-core" {
			foundPII = true
			break
		}
	}
	if !foundPII {
		t.Errorf("Expected PII detection for SSN, got %d results: %+v", len(result.Results), result.Results)
	}
}

func TestDetectSecrets(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Test AWS key detection
	result, err := d.Detect("My AWS key is AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}

	foundSecret := false
	for _, r := range result.Results {
		if r.Category == "secret" || r.Category == "secret_aws_key" {
			foundSecret = true
			break
		}
	}
	if !foundSecret {
		t.Errorf("Expected secret detection for AWS key, got %d results: %+v", len(result.Results), result.Results)
	}
}

func TestDetectCleanText(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Clean text should have zero or very few detections
	result, err := d.Detect("What is the weather today?")
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}

	// Clean text should not be blocked
	if result.Blocked {
		t.Errorf("Clean text should not be blocked, got: %+v", result)
	}
}

func TestDetectEmpty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	result, err := d.Detect("")
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}
	if result.TotalDetections != 0 {
		t.Errorf("Empty text should have 0 detections, got %d", result.TotalDetections)
	}
}

func TestDetectMultipleThreats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Text with both PII and a secret
	result, err := d.Detect("My SSN is 123-45-6789 and my AWS key is AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}

	if result.TotalDetections < 2 {
		t.Errorf("Expected at least 2 detections (PII + secret), got %d", result.TotalDetections)
	}

	if len(result.PIICategories) == 0 {
		t.Errorf("Expected PII categories, got none")
	}

	if len(result.SecretTypes) == 0 {
		t.Errorf("Expected secret types, got none")
	}
}