// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"context"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if !cfg.EnablePII {
		t.Error("DefaultConfig EnablePII should be true")
	}
	if !cfg.EnableSecrets {
		t.Error("DefaultConfig EnableSecrets should be true")
	}
	if !cfg.EnableXSS {
		t.Error("DefaultConfig EnableXSS should be true")
	}
	if !cfg.EnableCompliance {
		t.Error("DefaultConfig EnableCompliance should be true")
	}
	if !cfg.EnableML {
		t.Error("DefaultConfig EnableML should be true")
	}
	if cfg.MLThreshold != 0.7 {
		t.Errorf("DefaultConfig MLThreshold = %f, want 0.7", cfg.MLThreshold)
	}
	if !cfg.ShadowMode {
		t.Error("DefaultConfig ShadowMode should be true")
	}
	if cfg.StrictMode {
		t.Error("DefaultConfig StrictMode should be false")
	}
}

func TestNewWithDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false // Disable ML for testing (no model file)

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

func TestNewWithNilConfig(t *testing.T) {
	d, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil) failed: %v", err)
	}
	if d == nil {
		t.Fatal("New(nil) returned nil detector")
	}
}

func TestCompDetectEmpty(t *testing.T) {
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
	if result.Blocked {
		t.Error("Empty text should not be blocked")
	}
}

func TestCompDetectCleanText(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	result, err := d.Detect("What is the weather today?")
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}
	if result.Blocked {
		t.Errorf("Clean text should not be blocked, got: %+v", result)
	}
}

func TestCompDetectPII(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

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

	if len(result.PIICategories) == 0 {
		t.Error("Expected PII categories to be populated")
	}
}

func TestCompDetectSecrets(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

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

	if len(result.SecretTypes) == 0 {
		t.Error("Expected secret types to be populated")
	}
}

func TestCompDetectMultipleThreats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	result, err := d.Detect("My SSN is 123-45-6789 and my AWS key is AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}

	if result.TotalDetections < 2 {
		t.Errorf("Expected at least 2 detections (PII + secret), got %d", result.TotalDetections)
	}

	if len(result.PIICategories) == 0 {
		t.Error("Expected PII categories")
	}

	if len(result.SecretTypes) == 0 {
		t.Error("Expected secret types")
	}
}

func TestDetectWithContext(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	result, err := d.DetectWithContext(ctx, "Hello world")
	if err != nil {
		t.Fatalf("DetectWithContext() failed: %v", err)
	}
	if result == nil {
		t.Fatal("DetectWithContext() returned nil")
	}
}

func TestDetectWithContextEmpty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()
	result, err := d.DetectWithContext(ctx, "")
	if err != nil {
		t.Fatalf("DetectWithContext() failed: %v", err)
	}
	if result.TotalDetections != 0 {
		t.Errorf("Empty text should have 0 detections, got %d", result.TotalDetections)
	}
}

func TestDetectBatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	texts := []string{
		"Hello world",
		"My SSN is 123-45-6789",
		"Clean text",
	}

	results, err := d.DetectBatch(texts)
	if err != nil {
		t.Fatalf("DetectBatch() failed: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}
}

func TestDetectBatchEmpty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	results, err := d.DetectBatch([]string{})
	if err != nil {
		t.Fatalf("DetectBatch() failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(results))
	}
}

func TestDetectBatchSingle(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	results, err := d.DetectBatch([]string{"What is the weather?"})
	if err != nil {
		t.Fatalf("DetectBatch() failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
}

func TestResultStruct(t *testing.T) {
	r := Result{
		Category:    "pii",
		Severity:    "high",
		Confidence:  0.95,
		Text:        "123-45-6789",
		Rule:        "us-ssn",
		IsThreat:    true,
		Blocked:     true,
		BlockReason: "PII detected",
		MLScore:     0.0,
	}
	if r.Category != "pii" {
		t.Errorf("Category = %q", r.Category)
	}
	if r.Severity != "high" {
		t.Errorf("Severity = %q", r.Severity)
	}
	if r.Confidence != 0.95 {
		t.Errorf("Confidence = %f", r.Confidence)
	}
	if !r.IsThreat {
		t.Error("IsThreat should be true")
	}
	if !r.Blocked {
		t.Error("Blocked should be true")
	}
}

func TestSummaryStruct(t *testing.T) {
	s := Summary{
		TotalDetections: 5,
		Blocked:         true,
		BlockReason:     "PII detected",
		Results: []Result{
			{Category: "pii", Severity: "high", Text: "SSN"},
			{Category: "secret", Severity: "critical", Text: "AWS key"},
		},
		PIICategories: []string{"us-ssn"},
		SecretTypes:   []string{"aws_access_key"},
		Compliance:    map[string]bool{"pci-dss": true, "hipaa": false},
		MLScore:       0.85,
		LatencyMs:     42,
	}
	if s.TotalDetections != 5 {
		t.Errorf("TotalDetections = %d", s.TotalDetections)
	}
	if !s.Blocked {
		t.Error("Blocked should be true")
	}
	if s.BlockReason != "PII detected" {
		t.Errorf("BlockReason = %q", s.BlockReason)
	}
	if len(s.Results) != 2 {
		t.Errorf("Results = %d", len(s.Results))
	}
	if len(s.PIICategories) != 1 {
		t.Errorf("PIICategories = %d", len(s.PIICategories))
	}
	if len(s.SecretTypes) != 1 {
		t.Errorf("SecretTypes = %d", len(s.SecretTypes))
	}
	if s.Compliance["pci-dss"] != true {
		t.Error("Compliance pci-dss should be true")
	}
	if s.Compliance["hipaa"] != false {
		t.Error("Compliance hipaa should be false")
	}
	if s.MLScore != 0.85 {
		t.Errorf("MLScore = %f", s.MLScore)
	}
	if s.LatencyMs != 42 {
		t.Errorf("LatencyMs = %d", s.LatencyMs)
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := Config{
		EnableML:         true,
		ModelPath:        "/path/to/model.onnx",
		MLThreshold:      0.8,
		ShadowMode:       true,
		EnablePII:        true,
		EnableSecrets:    true,
		EnableXSS:        true,
		EnableCompliance: true,
		StrictMode:       false,
	}
	if !cfg.EnablePII {
		t.Error("EnablePII should be true")
	}
	if !cfg.EnableSecrets {
		t.Error("EnableSecrets should be true")
	}
	if !cfg.EnableXSS {
		t.Error("EnableXSS should be true")
	}
	if !cfg.EnableCompliance {
		t.Error("EnableCompliance should be true")
	}
	if cfg.MLThreshold != 0.8 {
		t.Errorf("MLThreshold = %f, want 0.8", cfg.MLThreshold)
	}
}

func TestSeverityIntToString(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "low"},
		{1, "low"},
		{2, "low"},
		{3, "medium"},
		{4, "high"},
		{5, "critical"},
		{6, "critical"},
		{10, "critical"},
	}
	for _, tt := range tests {
		result := severityIntToString(tt.input)
		if result != tt.expected {
			t.Errorf("severityIntToString(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestDetectXSS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableML = false
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	result, err := d.Detect(`<script>alert('xss')</script>`)
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}
	if result.TotalDetections == 0 {
		t.Error("Expected XSS detection")
	}
}

func TestNewWithCustomConfig(t *testing.T) {
	cfg := &Config{
		EnablePII:        true,
		EnableSecrets:    true,
		EnableXSS:        true,
		EnableCompliance: false,
		EnableML:         false,
		StrictMode:       true,
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New() with custom config failed: %v", err)
	}
	if d == nil {
		t.Fatal("New() returned nil")
	}
}
