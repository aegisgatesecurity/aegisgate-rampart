// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Anonymized Metrics Tests
// =========================================================================

package metrics

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector(true, "")
	defer c.Close()
	
	if c == nil {
		t.Fatal("Expected non-nil collector")
	}
	if !c.enabled {
		t.Error("Expected enabled to be true")
	}
	if c.endpoint != DefaultMetricsEndpoint {
		t.Errorf("endpoint = %s, want %s", c.endpoint, DefaultMetricsEndpoint)
	}
	if c.domainCache == nil {
		t.Error("Expected non-nil domainCache")
	}
	
	t.Logf("✓ Collector created with default endpoint")
}

func TestNewCollector_CustomEndpoint(t *testing.T) {
	customEndpoint := "https://custom.example.com/metrics"
	c := NewCollector(true, customEndpoint)
	defer c.Close()
	
	if c.endpoint != customEndpoint {
		t.Errorf("endpoint = %s, want %s", c.endpoint, customEndpoint)
	}
	
	t.Logf("✓ Collector created with custom endpoint")
}

func TestCollector_Disabled(t *testing.T) {
	c := NewCollector(false, "")
	defer c.Close()
	
	c.RecordDetection("api.openai.com", "pii_ssn", "critical", true)
	
	if c.GetQueueLength() != 0 {
		t.Error("Expected queue to be empty when disabled")
	}
	
	t.Logf("✓ Disabled collector drops metrics")
}

func TestCollector_RecordDetection(t *testing.T) {
	var recorded []AnonymizedMetric
	var mu sync.Mutex
	
	c := NewCollector(true, "")
	c.sendFunc = func(batch []AnonymizedMetric) error {
		mu.Lock()
		defer mu.Unlock()
		recorded = append(recorded, batch...)
		return nil
	}
	defer c.Close()
	
	c.RecordDetection("api.openai.com", "pii_ssn", "critical", true)
	c.RecordDetection("claude.ai", "secret_aws_key", "high", false)
	
	// Force send
	c.Flush()
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(recorded) != 2 {
		t.Errorf("Recorded %d metrics, want 2", len(recorded))
	}
	
	// Verify anonymization
	for _, m := range recorded {
		if m.Version == "" {
			t.Error("Expected version to be set")
		}
		if m.Platform == "" {
			t.Error("Expected platform to be set")
		}
		if len(m.DomainHash) != DomainHashLength {
			t.Errorf("DomainHash length = %d, want %d", len(m.DomainHash), DomainHashLength)
		}
		if m.Category == "" {
			t.Error("Expected category to be set")
		}
		if m.Hour.IsZero() {
			t.Error("Expected hour to be set")
		}
		
		// Verify hour is rounded
		if m.Hour.Minute() != 0 || m.Hour.Second() != 0 {
			t.Error("Expected hour to be rounded to hour boundary")
		}
	}
	
	t.Logf("✓ Detections recorded and anonymized")
}

func TestCollector_RecordFalsePositive(t *testing.T) {
	var recorded []AnonymizedMetric
	
	c := NewCollector(true, "")
	c.sendFunc = func(batch []AnonymizedMetric) error {
		recorded = append(recorded, batch...)
		return nil
	}
	defer c.Close()
	
	c.RecordFalsePositive("api.openai.com", "pii_ssn", "critical", "send_anyway")
	c.Flush()
	
	if len(recorded) != 1 {
		t.Errorf("Recorded %d metrics, want 1", len(recorded))
	}
	
	m := recorded[0]
	if !m.FalsePositive {
		t.Error("Expected FalsePositive to be true")
	}
	if m.UserAction != "send_anyway" {
		t.Errorf("UserAction = %s, want send_anyway", m.UserAction)
	}
	
	t.Logf("✓ False positive recorded")
}

func TestHashDomain_Consistency(t *testing.T) {
	c := NewCollector(true, "")
	defer c.Close()
	
	hash1 := c.hashDomain("api.openai.com")
	hash2 := c.hashDomain("api.openai.com")
	
	if hash1 != hash2 {
		t.Error("Expected consistent hashing")
	}
	
	t.Logf("✓ Domain hashing consistent")
}

func TestHashDomain_Normalization(t *testing.T) {
	c := NewCollector(true, "")
	defer c.Close()
	
	tests := []struct {
		domain1 string
		domain2 string
		same    bool
	}{
		{"api.openai.com", "API.OPENAI.COM", true},
		{"www.claude.ai", "claude.ai", true},
		{"api.openai.com:443", "api.openai.com", true},
		{"api.openai.com", "claude.ai", false},
	}
	
	for _, tt := range tests {
		hash1 := c.hashDomain(tt.domain1)
		hash2 := c.hashDomain(tt.domain2)
		
		if tt.same && hash1 != hash2 {
			t.Errorf("%s and %s should hash to same value", tt.domain1, tt.domain2)
		}
		if !tt.same && hash1 == hash2 {
			t.Errorf("%s and %s should hash to different values", tt.domain1, tt.domain2)
		}
	}
	
	t.Logf("✓ Domain normalization working")
}

func TestHashDomain_Length(t *testing.T) {
	c := NewCollector(true, "")
	defer c.Close()
	
	hash := c.hashDomain("api.openai.com")
	
	if len(hash) != DomainHashLength {
		t.Errorf("Hash length = %d, want %d", len(hash), DomainHashLength)
	}
	
	// Verify it's hex
	for _, ch := range hash {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			t.Errorf("Hash contains non-hex character: %c", ch)
		}
	}
	
	t.Logf("✓ Domain hash is %d hex chars", DomainHashLength)
}

func TestCollector_BatchSending(t *testing.T) {
	var batchesSent int
	var mu sync.Mutex
	
	c := NewCollector(true, "")
	c.sendFunc = func(batch []AnonymizedMetric) error {
		mu.Lock()
		defer mu.Unlock()
		batchesSent++
		return nil
	}
	defer c.Close()
	
	// Record enough to trigger batch send
	for i := 0; i < BatchSize*2; i++ {
		c.RecordDetection("test.example.com", "pii", "low", false)
	}
	
	// Wait for async sends
	time.Sleep(100 * time.Millisecond)
	
	mu.Lock()
	batches := batchesSent
	mu.Unlock()
	
	if batches < 2 {
		t.Errorf("Expected at least 2 batches, got %d", batches)
	}
	
	t.Logf("✓ Batch sending working (%d batches)", batches)
}

func TestCollector_Flush(t *testing.T) {
	var flushed bool
	
	c := NewCollector(true, "")
	c.sendFunc = func(batch []AnonymizedMetric) error {
		flushed = true
		return nil
	}
	
	c.RecordDetection("test.example.com", "pii", "low", false)
	c.Flush()
	
	if !flushed {
		t.Error("Expected Flush to send metrics")
	}
	if c.GetQueueLength() != 0 {
		t.Error("Expected queue to be empty after flush")
	}
	
	t.Logf("✓ Flush working")
}

func TestCollector_SetEnabled(t *testing.T) {
	c := NewCollector(false, "")
	defer c.Close()
	
	if c.IsEnabled() {
		t.Error("Expected enabled to be false")
	}
	
	c.SetEnabled(true)
	if !c.IsEnabled() {
		t.Error("Expected enabled to be true after SetEnabled(true)")
	}
	
	c.SetEnabled(false)
	if c.IsEnabled() {
		t.Error("Expected enabled to be false after SetEnabled(false)")
	}
	
	t.Logf("✓ SetEnabled working")
}

func TestCollector_ContextCancellation(t *testing.T) {
	c := NewCollector(true, "")
	
	// Cancel context immediately
	c.cancel()
	
	// Try to record (should not panic)
	c.RecordDetection("test.example.com", "pii", "low", false)
	
	// Close should not panic
	c.Close()
	
	t.Logf("✓ Context cancellation handled")
}

func TestAnonymizedMetric_Struct(t *testing.T) {
	metric := AnonymizedMetric{
		Version:       "0.5.0",
		Platform:      "linux-amd64",
		DomainHash:    "a1b2c3d4e5f67890",
		Category:      "pii_ssn",
		Severity:      "critical",
		Blocked:       true,
		Hour:          time.Now().Truncate(time.Hour),
		FalsePositive: true,
		UserAction:    "send_anyway",
	}
	
	if metric.Version != "0.5.0" {
		t.Errorf("Version = %s", metric.Version)
	}
	if !metric.FalsePositive {
		t.Error("Expected FalsePositive to be true")
	}
	
	t.Logf("✓ AnonymizedMetric struct working")
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"API.OpenAI.com", "api.openai.com"},
		{"www.Claude.ai", "claude.ai"},
		{"api.openai.com:443", "api.openai.com"},
		{"Gemini.Google.com", "gemini.google.com"},
	}
	
	for _, tt := range tests {
		result := normalizeDomain(tt.input)
		if result != tt.expect {
			t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, result, tt.expect)
		}
	}
	
	t.Logf("✓ normalizeDomain working")
}

func TestGetPlatform(t *testing.T) {
	platform := getPlatform()
	if platform == "" {
		t.Error("Expected non-empty platform")
	}
	if !strings.Contains(platform, "-") {
		t.Error("Expected platform to contain OS-ARCH format")
	}
	
	t.Logf("✓ getPlatform() = %s", platform)
}

func TestCollector_ConcurrentAccess(t *testing.T) {
	c := NewCollector(true, "")
	c.sendFunc = func(batch []AnonymizedMetric) error {
		return nil
	}
	defer c.Close()
	
	// Record from multiple goroutines
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.RecordDetection("test.example.com", "pii", "low", false)
			}
		}(i)
	}
	
	wg.Wait()
	c.Flush()
	
	t.Logf("✓ Concurrent access safe")
}
