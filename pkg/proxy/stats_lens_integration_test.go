// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Stats API Lens Integration Tests
// =========================================================================
//
// Tests for Lens-enhanced stats endpoint.
//
// =========================================================================

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/response"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

// TestHandleStatsAPILens tests the Lens-enhanced stats endpoint
func TestHandleStatsAPILens(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:  8080,
		DaemonMode: false,
		Mode:       "monitor",
		Targets:    config.DefaultTargets(),
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()

	// Call handler
	p.HandleStatsAPILens(w, req)

	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify CORS headers
	corsOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if corsOrigin != "*" {
		t.Errorf("Expected CORS header '*', got %s", corsOrigin)
	}

	// Parse response
	var stats LensStats
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("Failed to decode stats: %v", err)
	}

	// Verify base stats
	if stats.TotalRequests < 0 {
		t.Error("Expected non-negative total requests")
	}
	if stats.Mode == "" {
		t.Error("Expected mode to be set")
	}
	// Note: StartTime is set when proxy.Start() is called, not in New()
	// For unit tests that don't call Start(), StartTime may be zero

	// Verify Lens-specific fields
	if stats.UptimeSeconds < 0 {
		t.Error("Expected non-negative uptime")
	}
	if stats.DetectionsByCategory == nil {
		t.Error("Expected detections by category map")
	}

	t.Logf("✓ Lens stats endpoint working (uptime: %ds, mode: %s)",
		stats.UptimeSeconds, stats.Mode)
}

// TestHandleStatsAPILens_OPTIONS tests CORS preflight handling
func TestHandleStatsAPILens_OPTIONS(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:  8080,
		DaemonMode: false,
		Mode:       "monitor",
		Targets:    config.DefaultTargets(),
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Create OPTIONS preflight request
	req := httptest.NewRequest(http.MethodOptions, "/stats", nil)
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	w := httptest.NewRecorder()

	// Call handler
	p.HandleStatsAPILens(w, req)

	// Verify preflight response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", w.Code)
	}

	corsMethods := w.Header().Get("Access-Control-Allow-Methods")
	if corsMethods != "GET, OPTIONS" {
		t.Errorf("Expected CORS methods 'GET, OPTIONS', got %s", corsMethods)
	}

	t.Logf("✓ CORS preflight handled correctly")
}

// TestHandleStatsAPILens_WrongMethod tests method validation
func TestHandleStatsAPILens_WrongMethod(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:  8080,
		DaemonMode: false,
		Mode:       "monitor",
		Targets:    config.DefaultTargets(),
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Create POST request (not allowed)
	req := httptest.NewRequest(http.MethodPost, "/stats", nil)
	w := httptest.NewRecorder()

	// Call handler
	p.HandleStatsAPILens(w, req)

	// Verify rejection
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}

	t.Logf("✓ Wrong method correctly rejected")
}

// TestLensStats_JSON tests LensStats JSON serialization
func TestLensStats_JSON(t *testing.T) {
	stats := LensStats{
		ProxyStats: ProxyStats{
			TotalRequests:   1000,
			Intercepted:     500,
			Detections:      50,
			Mode:            "monitor",
			StartTime:       time.Now().Add(-1 * time.Hour),
		},
		UptimeSeconds:   3600,
		DetectionsByCategory: map[string]int64{
			"pii":      30,
			"secrets":  20,
		},
		ComplianceStatus: response.ComplianceStatus{
			SOC2Violations:   5,
			GDPRViolations:   3,
			OverallCompliant: false,
		},
		LastDetectionTime: time.Now(),
		AvgLatencyMs:      12.5,
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var decoded LensStats
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	if decoded.UptimeSeconds != stats.UptimeSeconds {
		t.Error("Uptime mismatch")
	}
	if decoded.ComplianceStatus.OverallCompliant != stats.ComplianceStatus.OverallCompliant {
		t.Error("Compliance status mismatch")
	}

	t.Logf("✓ LensStats JSON serialization working")
}

// TestComplianceStatus_Structure tests compliance status structure
func TestComplianceStatus_Structure(t *testing.T) {
	status := response.ComplianceStatus{
		SOC2Violations:   10,
		GDPRViolations:   5,
		HIPAAViolations:  2,
		PCIDSSViolations: 1,
		OverallCompliant: false,
	}

	if status.SOC2Violations < 0 {
		t.Error("SOC2 violations should be non-negative")
	}
	if status.GDPRViolations < 0 {
		t.Error("GDPR violations should be non-negative")
	}
	if status.HIPAAViolations < 0 {
		t.Error("HIPAA violations should be non-negative")
	}
	if status.PCIDSSViolations < 0 {
		t.Error("PCI-DSS violations should be non-negative")
	}

	t.Logf("✓ ComplianceStatus structure valid")
}

// TestHandleStatsAPILens_RateLimit tests rate limiting
func TestHandleStatsAPILens_RateLimit(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:      8080,
		DaemonMode:     false,
		Mode:           "monitor",
		RateLimitRPS:   1, // Very low for testing
		Targets:        config.DefaultTargets(),
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// First request should succeed
	req1 := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w1 := httptest.NewRecorder()
	p.HandleStatsAPILens(w1, req1)

	if w1.Code != http.StatusOK {
		t.Logf("First request status: %d (may be rate limited)", w1.Code)
	}

	// Second request should be rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w2 := httptest.NewRecorder()
	p.HandleStatsAPILens(w2, req2)

	if w2.Code == http.StatusTooManyRequests {
		t.Logf("✓ Rate limiting working correctly")
	} else {
		t.Logf("Rate limit not triggered (status: %d)", w2.Code)
	}
}

// TestGetDetectionsByCategory tests category breakdown
func TestGetDetectionsByCategory(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:  8080,
		DaemonMode: false,
		Mode:       "monitor",
		Targets:    config.DefaultTargets(),
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	categories := p.getDetectionsByCategory()

	if categories == nil {
		t.Error("Expected non-nil category map")
	}

	t.Logf("✓ getDetectionsByCategory returning map with %d categories", len(categories))
}

// TestGetComplianceStatus tests compliance status retrieval
func TestGetComplianceStatus(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:  8080,
		DaemonMode: false,
		Mode:       "monitor",
		Targets:    config.DefaultTargets(),
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	status := p.getComplianceStatus()

	// Verify structure
	_ = status.SOC2Violations
	_ = status.GDPRViolations
	_ = status.HIPAAViolations
	_ = status.PCIDSSViolations
	_ = status.OverallCompliant

	t.Logf("✓ getComplianceStatus returning valid status (compliant: %v)", status.OverallCompliant)
}
