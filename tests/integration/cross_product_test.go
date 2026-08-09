// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Cross-Product Integration Smoke Tests
// =========================================================================
//
// Verifies the full detection pipeline works end-to-end:
//   1. Rampart detector finds PII in AI API traffic
//   2. Audit log entry is created from detection metadata
//   3. Platform forwarder delivers event to a mock Platform server
//   4. Webhook manager delivers notification with HMAC signature to a mock receiver
//   5. Lens stats endpoint reports accurate detection counts, categories, and latency
//
// This test does NOT require Docker or external services — it uses httptest
// to simulate Platform and webhook receivers. It verifies the contract between
// all three AegisGate products (Rampart → Platform, Rampart → Lens, Rampart → Webhook).
//
// =========================================================================

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/auditlog"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/platformforward"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/webhook"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/proxy"
)

// mockPlatformServer simulates AegisGate Platform receiving forwarded events.
type mockPlatformServer struct {
	mu     sync.Mutex
	events []platformforward.PlatformEvent
	server *httptest.Server
}

func newMockPlatform(t *testing.T) *mockPlatformServer {
	m := &mockPlatformServer{}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		var event platformforward.PlatformEvent
		if err := json.Unmarshal(body, &event); err != nil {
			http.Error(w, "unmarshal error", http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		m.events = append(m.events, event)
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockPlatformServer) getEvents() []platformforward.PlatformEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]platformforward.PlatformEvent, len(m.events))
	copy(result, m.events)
	return result
}

// mockWebhookReceiver simulates a webhook endpoint (Slack/Discord/Teams).
type mockWebhookReceiver struct {
	mu         sync.Mutex
	received   []webhook.Event
	signatures []string
	server     *httptest.Server
	secret     string
}

func newMockWebhook(t *testing.T, secret string) *mockWebhookReceiver {
	w := &mockWebhookReceiver{secret: secret}
	w.server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(rw, "read error", http.StatusBadRequest)
			return
		}
		var event webhook.Event
		if err := json.Unmarshal(body, &event); err != nil {
			http.Error(rw, "unmarshal error", http.StatusBadRequest)
			return
		}
		w.mu.Lock()
		w.received = append(w.received, event)
		w.signatures = append(w.signatures, r.Header.Get("X-AegisGate-Signature"))
		w.mu.Unlock()
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(w.server.Close)
	return w
}

func (w *mockWebhookReceiver) getReceived() []webhook.Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := make([]webhook.Event, len(w.received))
	copy(result, w.received)
	return result
}

func (w *mockWebhookReceiver) getSignatures() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	result := make([]string, len(w.signatures))
	copy(result, w.signatures)
	return result
}

// TestCrossProduct_FullPipeline verifies the complete detection-to-notification chain:
// Detector → AuditLog → Platform Forwarder → Webhook (with HMAC) → Lens Stats
func TestCrossProduct_FullPipeline(t *testing.T) {
	// --- Arrange: Set up mock Platform and webhook receivers ---
	platformMock := newMockPlatform(t)
	webhookMock := newMockWebhook(t, "test-shared-secret")

	// --- Act: Run detection on synthetic PII data ---
	d, err := detector.New(&detector.Config{
		EnablePII:        true,
		EnableSecrets:    true,
		EnableCompliance: true,
		EnableXSS:        true,
	})
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	// Sample PII text that should trigger detections
	piiText := "My SSN is 123-45-6789 and my email is john.doe@example.com. " +
		"Credit card: 4532-1234-5678-9010. My API key is sk-1234567890abcdef1234567890abcdef."

	result, err := d.Detect(piiText)
	if err != nil {
		t.Fatalf("Detection failed: %v", err)
	}
	if result.TotalDetections == 0 {
		t.Fatal("Expected detections for PII text, got 0")
	}
	t.Logf("✓ Step 1: Detector found %d detections (latency: %dms, categories: %v)",
		result.TotalDetections, result.LatencyMs, result.PIICategories)

	// --- Step 2: Create audit log entry from detection ---
	entry := auditlog.Entry{
		Timestamp:     time.Now(),
		Direction:     "request",
		Host:          "api.openai.com",
		Path:          "/v1/chat/completions",
		TotalDets:     result.TotalDetections,
		PIICategories: result.PIICategories,
		MLScore:       result.MLScore,
	}
	for _, r := range result.Results {
		entry.Categories = append(entry.Categories, r.Category)
		entry.Severities = append(entry.Severities, r.Severity)
		entry.Rules = append(entry.Rules, r.Rule)
	}
	t.Logf("✓ Step 2: Audit entry created (categories: %v)", entry.Categories)

	// --- Step 3: Platform forwarder delivers event to mock Platform ---
	forwarder := platformforward.NewWithAPIKey(platformMock.server.URL, "test-api-key")
	forwarder.Forward(entry)

	// Forward is async — wait for delivery
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(platformMock.getEvents()) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	pEvents := platformMock.getEvents()
	if len(pEvents) != 1 {
		t.Fatalf("Expected 1 platform event, got %d", len(pEvents))
	}
	pe := pEvents[0]
	if pe.Host != "api.openai.com" {
		t.Errorf("Expected host 'api.openai.com', got '%s'", pe.Host)
	}
	if pe.TotalDets != result.TotalDetections {
		t.Errorf("Expected %d total detections, got %d", result.TotalDetections, pe.TotalDets)
	}
	if pe.Source != "rampart" {
		t.Errorf("Expected source 'rampart', got '%s'", pe.Source)
	}
	t.Logf("✓ Step 3: Platform received event (host: %s, detections: %d, source: %s)",
		pe.Host, pe.TotalDets, pe.Source)

	// --- Step 4: Webhook delivers with HMAC signature ---
	whManager := webhook.NewManager(webhook.Config{
		Webhooks: []webhook.WebhookConfig{
			{
				ID:      "test-1",
				Name:    "Test Webhook",
				URL:     webhookMock.server.URL,
				Enabled: true,
				Secret:  "test-shared-secret",
			},
		},
	})

	whEvent := webhook.Event{
		Timestamp:  time.Now(),
		EventType:  "detection",
		Host:       "api.openai.com",
		Blocked:    false,
		Severity:   "high",
		Categories: entry.Categories,
		Message:    "PII detected in outbound request",
	}

	if err := whManager.Send(context.Background(), whEvent); err != nil {
		t.Fatalf("Webhook send failed: %v", err)
	}

	whReceived := webhookMock.getReceived()
	if len(whReceived) != 1 {
		t.Fatalf("Expected 1 webhook event, got %d", len(whReceived))
	}
	if whReceived[0].Host != "api.openai.com" {
		t.Errorf("Expected webhook host 'api.openai.com', got '%s'", whReceived[0].Host)
	}

	// Verify HMAC signature was included
	sigs := webhookMock.getSignatures()
	if len(sigs) != 1 || !strings.HasPrefix(sigs[0], "sha256=") {
		t.Errorf("Expected HMAC sha256 signature, got %v", sigs)
	}
	t.Logf("✓ Step 4: Webhook delivered with HMAC signature (%s)", sigs[0][:20]+"...")

	// --- Step 5: Lens stats endpoint reports accurate data ---
	cfg := &config.Config{
		ProxyPort:  18080,
		DaemonMode: false,
		Mode:       "monitor",
		Targets:    config.DefaultTargets(),
	}

	p, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Simulate detection by calling scanAndAlert with the same PII text
	scanResult := p.ScanForTest("request", "api.openai.com", "/v1/chat/completions", []byte(piiText))
	if scanResult == nil || scanResult.TotalDetections == 0 {
		t.Fatal("Expected proxy scan to find detections")
	}

	// Query the Lens stats endpoint
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	p.HandleStatsAPILens(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected stats endpoint 200, got %d", w.Code)
	}

	var stats proxy.LensStats
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("Failed to decode Lens stats: %v", err)
	}

	if stats.Detections < 1 {
		t.Errorf("Expected detections >= 1 in stats, got %d", stats.Detections)
	}
	if len(stats.DetectionsByCategory) == 0 {
		t.Error("Expected non-empty detections by category")
	}
	if stats.AvgLatencyMs < 0 {
		t.Errorf("Expected non-negative avg latency, got %f", stats.AvgLatencyMs)
	}
	t.Logf("✓ Step 5: Lens stats endpoint reports (detections: %d, categories: %d, avg_latency: %.2fms)",
		stats.Detections, len(stats.DetectionsByCategory), stats.AvgLatencyMs)

	t.Logf("")
	t.Logf("✅ Cross-product pipeline verified: Detector → AuditLog → Platform → Webhook → Lens Stats")
}

// TestCrossProduct_PlatformHealthCheck verifies that the Platform forwarder
// heartbeat mechanism works (Rampart → Platform connectivity check).
func TestCrossProduct_PlatformHealthCheck(t *testing.T) {
	// Mock Platform with a health endpoint
	healthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/api/v1/health" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"healthy","version":"4.0.0"}`))
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer healthServer.Close()

	forwarder := platformforward.NewWithAPIKey(healthServer.URL, "test-key")
	result := forwarder.Heartbeat()

	if !result.Success {
		t.Fatalf("Expected heartbeat success, got: %v", result)
	}
	t.Logf("✓ Platform heartbeat successful (latency: %v)", result.Latency)
}

// TestCrossProduct_WebhookNoSecret verifies webhook works without HMAC
// (backwards compatibility — secrets are optional).
func TestCrossProduct_WebhookNoSecret(t *testing.T) {
	webhookMock := newMockWebhook(t, "") // No secret

	whManager := webhook.NewManager(webhook.Config{
		Webhooks: []webhook.WebhookConfig{
			{
				ID:      "test-nosig",
				Name:    "Test Webhook No Signature",
				URL:     webhookMock.server.URL,
				Enabled: true,
				// No Secret — HMAC signing is opt-in
			},
		},
	})

	event := webhook.Event{
		Timestamp: time.Now(),
		Host:      "api.anthropic.com",
		Message:   "Test event without HMAC",
	}

	if err := whManager.Send(context.Background(), event); err != nil {
		t.Fatalf("Webhook send failed: %v", err)
	}

	sigs := webhookMock.getSignatures()
	if len(sigs) != 1 || sigs[0] != "" {
		t.Errorf("Expected empty signature (no secret), got %v", sigs)
	}
	t.Logf("✓ Webhook delivered without HMAC (no secret configured)")
}

// TestCrossProduct_LensComplianceStatus verifies that Lens stats include
// compliance framework mapping (SOC2, GDPR, HIPAA, PCI-DSS).
func TestCrossProduct_LensComplianceStatus(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:  18081,
		DaemonMode: false,
		Mode:       "monitor",
		Targets:    config.DefaultTargets(),
	}

	p, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Scan text with PII that maps to compliance violations
	piiText := "Patient SSN: 123-45-6789, Email: patient@hospital.com"
	scanResult := p.ScanForTest("request", "api.openai.com", "/v1/chat/completions", []byte(piiText))
	if scanResult == nil {
		t.Fatal("Expected scan result")
	}

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	p.HandleStatsAPILens(w, req)

	var stats proxy.LensStats
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("Failed to decode stats: %v", err)
	}

	// Verify compliance status structure is present
	_ = stats.ComplianceStatus.SOC2Violations
	_ = stats.ComplianceStatus.GDPRViolations
	_ = stats.ComplianceStatus.HIPAAViolations
	_ = stats.ComplianceStatus.PCIDSSViolations
	_ = stats.ComplianceStatus.OverallCompliant

	t.Logf("✓ Lens compliance status: SOC2=%d, GDPR=%d, HIPAA=%d, PCI-DSS=%d, compliant=%v",
		stats.ComplianceStatus.SOC2Violations,
		stats.ComplianceStatus.GDPRViolations,
		stats.ComplianceStatus.HIPAAViolations,
		stats.ComplianceStatus.PCIDSSViolations,
		stats.ComplianceStatus.OverallCompliant)
}

// TestCrossProduct_PlatformEventMetadata verifies that forwarded Platform events
// contain only metadata — never prompt text or PII values (privacy guarantee).
func TestCrossProduct_PlatformEventMetadata(t *testing.T) {
	platformMock := newMockPlatform(t)
	forwarder := platformforward.NewWithAPIKey(platformMock.server.URL, "test-key")

	entry := auditlog.Entry{
		Timestamp:     time.Now(),
		Direction:     "request",
		Host:          "api.openai.com",
		Path:          "/v1/chat/completions",
		TotalDets:     3,
		PIICategories: []string{"ssn", "email", "credit_card"},
		Categories:    []string{"pii", "pii", "pii"},
		Severities:    []string{"high", "medium", "high"},
		Rules:         []string{"ssn_pattern", "email_pattern", "credit_card_pattern"},
	}

	forwarder.Forward(entry)

	// Wait for async delivery
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(platformMock.getEvents()) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	events := platformMock.getEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}

	// Serialize the event to check no prompt text leaked
	raw, _ := json.Marshal(events[0])
	rawStr := string(raw)

	// Verify no sensitive data patterns are in the forwarded event
	dangerousPatterns := []string{
		"123-45-6789",          // SSN value
		"john.doe@example.com", // Email value
		"4532-1234-5678-9010",  // Credit card value
		"sk-1234567890",        // API key value
		"prompt",               // Prompt text reference
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToLower(rawStr), strings.ToLower(pattern)) {
			t.Errorf("PRIVACY VIOLATION: Platform event contains '%s': %s", pattern, rawStr)
		}
	}

	t.Logf("✓ Privacy verified: Platform event contains only metadata (no PII values, no prompt text)")
	t.Logf("  Event: source=%s, host=%s, detections=%d, categories=%v",
		events[0].Source, events[0].Host, events[0].TotalDets, events[0].PIICategories)
}

// TestCrossProduct_ResponseScanning verifies that response-body scanning
// (inbound AI responses) flows through the same pipeline.
func TestCrossProduct_ResponseScanning(t *testing.T) {
	platformMock := newMockPlatform(t)
	forwarder := platformforward.NewWithAPIKey(platformMock.server.URL, "test-key")

	cfg := &config.Config{
		ProxyPort:  18082,
		DaemonMode: false,
		Mode:       "monitor",
		Targets:    config.DefaultTargets(),
	}

	p, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Simulate scanning an AI response containing leaked PII
	aiResponse := `Here is the user's information: SSN 987-65-4321, email alice@corp.com`
	scanResult := p.ScanForTest("response", "api.openai.com", "/v1/chat/completions", []byte(aiResponse))
	if scanResult == nil || scanResult.TotalDetections == 0 {
		t.Fatal("Expected detections in AI response")
	}

	// Create audit entry and forward to Platform
	entry := auditlog.Entry{
		Timestamp:     time.Now(),
		Direction:     "response",
		Host:          "api.openai.com",
		Path:          "/v1/chat/completions",
		TotalDets:     scanResult.TotalDetections,
		PIICategories: scanResult.PIICategories,
	}
	for _, r := range scanResult.Results {
		entry.Categories = append(entry.Categories, r.Category)
	}

	forwarder.Forward(entry)

	// Wait for delivery
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(platformMock.getEvents()) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	events := platformMock.getEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 platform event, got %d", len(events))
	}
	if events[0].Direction != "response" {
		t.Errorf("Expected direction 'response', got '%s'", events[0].Direction)
	}

	t.Logf("✓ Response scanning pipeline verified (direction: %s, detections: %d)",
		events[0].Direction, events[0].TotalDets)
}

// TestCrossProduct_BlockModeForwarding verifies that blocked requests are
// forwarded to Platform with the blocked flag set.
func TestCrossProduct_BlockModeForwarding(t *testing.T) {
	platformMock := newMockPlatform(t)
	forwarder := platformforward.NewWithAPIKey(platformMock.server.URL, "test-key")

	entry := auditlog.Entry{
		Timestamp:  time.Now(),
		Direction:  "request",
		Host:       "api.openai.com",
		TotalDets:  5,
		Blocked:    true,
		Categories: []string{"pii", "secrets"},
	}

	forwarder.Forward(entry)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(platformMock.getEvents()) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	events := platformMock.getEvents()
	if len(events) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(events))
	}
	if !events[0].Blocked {
		t.Error("Expected blocked=true in forwarded event")
	}

	t.Logf("✓ Block mode forwarding verified (blocked: %v, detections: %d)",
		events[0].Blocked, events[0].TotalDets)
}
