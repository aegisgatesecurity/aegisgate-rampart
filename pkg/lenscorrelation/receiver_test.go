// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart — Lens Signal Correlation Tests

package lenscorrelation

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandleSignal_Valid(t *testing.T) {
	rcv := NewSignalReceiver()
	server := httptest.NewServer(http.HandlerFunc(rcv.HandleSignal))
	defer server.Close()

	signal := LensSignal{
		HashedDomain: "abc123def456",
		Category:     "prompt_injection",
		Severity:     "high",
		RuleID:       "owasp_llm01_prompt_injection",
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Direction:    "page",
		Action:       "warned",
	}

	body, _ := json.Marshal(signal)
	resp, err := http.Post(server.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result CorrelationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if result.OriginalSeverity != "high" {
		t.Errorf("expected original severity high, got %s", result.OriginalSeverity)
	}
}

func TestHandleSignal_Options(t *testing.T) {
	rcv := NewSignalReceiver()
	server := httptest.NewServer(http.HandlerFunc(rcv.HandleSignal))
	defer server.Close()

	req, _ := http.NewRequest("OPTIONS", server.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204 for OPTIONS, got %d", resp.StatusCode)
	}

	// Check CORS headers
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected CORS Access-Control-Allow-Origin: *")
	}
}

func TestHandleSignal_MethodNotAllowed(t *testing.T) {
	rcv := NewSignalReceiver()
	server := httptest.NewServer(http.HandlerFunc(rcv.HandleSignal))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestHandleSignal_InvalidJSON(t *testing.T) {
	rcv := NewSignalReceiver()
	server := httptest.NewServer(http.HandlerFunc(rcv.HandleSignal))
	defer server.Close()

	resp, err := http.Post(server.URL, "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestHandleSignal_MissingFields(t *testing.T) {
	rcv := NewSignalReceiver()
	server := httptest.NewServer(http.HandlerFunc(rcv.HandleSignal))
	defer server.Close()

	// Missing hashed_domain
	signal := LensSignal{Category: "test", Severity: "high"}
	body, _ := json.Marshal(signal)
	resp, err := http.Post(server.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", resp.StatusCode)
	}
}

func TestHandleSignal_InvalidSeverity(t *testing.T) {
	rcv := NewSignalReceiver()
	server := httptest.NewServer(http.HandlerFunc(rcv.HandleSignal))
	defer server.Close()

	signal := LensSignal{
		HashedDomain: "abc123",
		Category:     "test",
		Severity:     "extreme", // invalid
	}
	body, _ := json.Marshal(signal)
	resp, err := http.Post(server.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid severity, got %d", resp.StatusCode)
	}
}

func TestCorrelate_NoMatch(t *testing.T) {
	rcv := NewSignalReceiver()

	signal := LensSignal{
		HashedDomain: "domain-a",
		Severity:     "high",
		Category:     "prompt_injection",
	}

	result := rcv.ProcessSignal(signal)

	if len(result.MatchingDetections) != 0 {
		t.Errorf("expected 0 matching detections, got %d", len(result.MatchingDetections))
	}
	if result.Escalated {
		t.Error("should not escalate with no matches")
	}
}

func TestCorrelate_WithMatch(t *testing.T) {
	rcv := NewSignalReceiver()

	// Record a Rampart detection on the same domain
	rcv.RecordRampartDetection(RampartDetection{
		HashedDomain: "domain-x",
		Category:     "pii",
		Severity:     "high",
		RuleID:       "pii_ssn",
		Timestamp:    time.Now(),
		Direction:    "response",
	})

	// Send a Lens signal on the same domain
	signal := LensSignal{
		HashedDomain: "domain-x",
		Severity:     "high",
		Category:     "prompt_injection",
		RuleID:       "owasp_llm01",
	}

	result := rcv.ProcessSignal(signal)

	if len(result.MatchingDetections) != 1 {
		t.Fatalf("expected 1 matching detection, got %d", len(result.MatchingDetections))
	}
	if !result.Escalated {
		t.Error("expected escalation with dual high detections")
	}
	if result.EscalatedSeverity != "critical" {
		t.Errorf("expected escalated to critical, got %s", result.EscalatedSeverity)
	}
	if !result.RecommendBlock {
		t.Error("expected recommend block for dual high detections")
	}
}

func TestCorrelate_CriticalBlock(t *testing.T) {
	rcv := NewSignalReceiver()

	rcv.RecordRampartDetection(RampartDetection{
		HashedDomain: "domain-c",
		Severity:     "critical",
		Category:     "secrets",
		Timestamp:    time.Now(),
	})

	signal := LensSignal{
		HashedDomain: "domain-c",
		Severity:     "medium",
		Category:     "prompt_injection",
	}

	result := rcv.ProcessSignal(signal)

	if !result.RecommendBlock {
		t.Error("expected block for critical Rampart detection")
	}
}

func TestCorrelate_MediumMediumEscalation(t *testing.T) {
	rcv := NewSignalReceiver()

	rcv.RecordRampartDetection(RampartDetection{
		HashedDomain: "domain-m",
		Severity:     "medium",
		Category:     "pii",
		Timestamp:    time.Now(),
	})

	signal := LensSignal{
		HashedDomain: "domain-m",
		Severity:     "medium",
		Category:     "xss",
	}

	result := rcv.ProcessSignal(signal)

	if !result.Escalated {
		t.Error("expected escalation for medium+medium")
	}
	if result.EscalatedSeverity != "high" {
		t.Errorf("expected escalated to high, got %s", result.EscalatedSeverity)
	}
}

func TestCorrelate_DifferentDomainNoMatch(t *testing.T) {
	rcv := NewSignalReceiver()

	rcv.RecordRampartDetection(RampartDetection{
		HashedDomain: "domain-1",
		Severity:     "critical",
		Timestamp:    time.Now(),
	})

	signal := LensSignal{
		HashedDomain: "domain-2", // different domain
		Severity:     "high",
		Category:     "test",
	}

	result := rcv.ProcessSignal(signal)

	if len(result.MatchingDetections) != 0 {
		t.Errorf("expected 0 matches for different domain, got %d", len(result.MatchingDetections))
	}
}

func TestEscalateSeverity(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"low", "medium"},
		{"medium", "high"},
		{"high", "critical"},
		{"critical", "critical"}, // can't go higher
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		result := escalateSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("escalateSeverity(%s) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func TestShouldEscalate(t *testing.T) {
	tests := []struct {
		lens, rampart string
		expected      bool
	}{
		{"high", "high", true},
		{"critical", "medium", true},
		{"medium", "medium", true},
		{"medium", "high", false},
		{"low", "high", false},
		{"low", "low", false},
	}

	for _, tt := range tests {
		result := shouldEscalate(tt.lens, tt.rampart)
		if result != tt.expected {
			t.Errorf("shouldEscalate(%s, %s) = %v, expected %v", tt.lens, tt.rampart, result, tt.expected)
		}
	}
}

func TestGetStats(t *testing.T) {
	rcv := NewSignalReceiver()

	// Process some signals
	rcv.ProcessSignal(LensSignal{HashedDomain: "d1", Category: "c", Severity: "high"})
	rcv.ProcessSignal(LensSignal{HashedDomain: "d2", Category: "c", Severity: "low"})

	stats := rcv.GetStats()
	if stats.TotalSignals != 2 {
		t.Errorf("expected 2 total signals, got %d", stats.TotalSignals)
	}
}

func TestHandleHealthz(t *testing.T) {
	rcv := NewSignalReceiver()
	server := httptest.NewServer(http.HandlerFunc(rcv.HandleHealthz))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %v", result["status"])
	}
}

func TestPruneExpired(t *testing.T) {
	rcv := NewSignalReceiver()
	rcv.SetWindowDuration(1 * time.Second)

	// Add an old detection
	rcv.RecordRampartDetection(RampartDetection{
		HashedDomain: "old",
		Severity:     "high",
		Timestamp:    time.Now().Add(-10 * time.Second),
	})

	// Add a recent detection
	rcv.RecordRampartDetection(RampartDetection{
		HashedDomain: "new",
		Severity:     "high",
		Timestamp:    time.Now(),
	})

	// Wait a moment
	time.Sleep(10 * time.Millisecond)

	rcv.PruneExpired()

	if rcv.GetDetectionCount() != 1 {
		t.Errorf("expected 1 detection after prune, got %d", rcv.GetDetectionCount())
	}
}

func TestValidateSignal(t *testing.T) {
	tests := []struct {
		signal  LensSignal
		hasErr  bool
		errSubs string
	}{
		{LensSignal{HashedDomain: "d", Category: "c", Severity: "high"}, false, ""},
		{LensSignal{Category: "c", Severity: "high"}, true, "hashed_domain"},
		{LensSignal{HashedDomain: "d", Severity: "high"}, true, "category"},
		{LensSignal{HashedDomain: "d", Category: "c"}, true, "severity"},
		{LensSignal{HashedDomain: "d", Category: "c", Severity: "extreme"}, true, "invalid severity"},
	}

	for _, tt := range tests {
		err := validateSignal(tt.signal)
		if tt.hasErr && err == nil {
			t.Errorf("expected error containing '%s', got nil", tt.errSubs)
		}
		if !tt.hasErr && err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}
}
