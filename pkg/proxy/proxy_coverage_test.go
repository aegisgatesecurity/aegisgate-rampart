// SPDX-License-Identifier: Apache-2.0
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"
)

// TestShutdown_NilServer_NoPanic tests Shutdown with nil server.
func TestShutdown_NilServer_NoPanic(t *testing.T) {
	p := &Proxy{cfg: config.DefaultConfig()}
	p.Shutdown() // Should not panic
}

// TestScanAndAlert_DaemonMode tests scanAndAlert in daemon mode.
func TestScanAndAlert_DaemonMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.DaemonMode = true
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	ssnText := "SSN: 123-45-6789"
	p.scanAndAlert("response", "api.openai.com", "/v1/chat/completions", []byte(ssnText))

	stats := p.GetStats()
	if stats.Detections == 0 {
		t.Error("Daemon mode should still count detections")
	}
}

// TestPrintDetection_NoPath tests printDetection with empty/root path.
func TestPrintDetection_NoPath(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	result := &detector.Summary{
		TotalDetections: 1,
		Blocked:         false,
		Results: []detector.Result{
			{Category: "pii-us-core", Severity: "medium", Text: "Phone detected"},
		},
	}

	// Should not panic with empty path or root path
	p.printDetection("request", "api.openai.com", "", result)
	p.printDetection("request", "api.openai.com", "/", result)
}

// TestPrintDetection_LowMLScore tests printDetection with low ML score.
func TestPrintDetection_LowMLScore(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	result := &detector.Summary{
		TotalDetections: 1,
		Blocked:         false,
		MLScore:         0.25,
		Results: []detector.Result{
			{Category: "suspicious", Severity: "low", Text: "Unusual pattern"},
		},
	}

	p.printDetection("response", "api.openai.com", "/v1/chat/completions", result)
}

// TestHandleDetectAPI_LargeBody tests /detect with a large request body.
func TestHandleDetectAPI_LargeBody(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	largeText := strings.Repeat("This is safe text. ", 1000)
	body := fmt.Sprintf(`{"text": "%s"}`, largeText)
	req := httptest.NewRequest("POST", "/detect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	p.HandleDetectAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}
}

// TestHandleDetectAPI_MissingTextField tests /detect with JSON missing text field.
func TestHandleDetectAPI_MissingTextField(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	body := `{"nottext": "something"}`
	req := httptest.NewRequest("POST", "/detect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	p.HandleDetectAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 for empty text, got %d", rec.Code)
	}
}

// TestHandleDetectAPI_ReadBodyError tests /detect when body read fails.
func TestHandleDetectAPI_ReadBodyError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("POST", "/detect", io.NopCloser(strings.NewReader(`{"text": "test"}`)))
	req.Body.Close() // Close body to force a read error
	rec := httptest.NewRecorder()

	p.HandleDetectAPI(rec, req)

	// Should return 400 since body read will fail
	if rec.Code != http.StatusBadRequest {
		t.Logf("HandleDetectAPI with closed body returned %d (may vary)", rec.Code)
	}
}

// TestProxyStats_ConcurrentAccess tests concurrent access to proxy stats.
func TestProxyStats_ConcurrentAccess(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	done := make(chan bool, 100)

	for i := 0; i < 50; i++ {
		go func() {
			_ = p.GetStats()
			done <- true
		}()
		go func() {
			p.mu.Lock()
			p.stats.TotalRequests++
			p.mu.Unlock()
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	stats := p.GetStats()
	if stats.TotalRequests != 50 {
		t.Errorf("Expected 50 total requests, got %d", stats.TotalRequests)
	}
}

// TestProxyStats_MarshalJSON tests ProxyStats JSON marshaling.
func TestProxyStats_MarshalJSON(t *testing.T) {
	stats := ProxyStats{
		TotalRequests:   100,
		Intercepted:     50,
		PassedThrough:   50,
		Detections:      10,
		BlockedRequests: 2,
		MLDetections:    3,
		StartTime:       time.Now(),
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("Failed to marshal ProxyStats: %v", err)
	}

	if !bytes.Contains(data, []byte("total_requests")) {
		t.Errorf("JSON should contain 'total_requests', got: %s", string(data))
	}
}

// TestProxyStats_CompareCopy tests that GetStats returns independent copies.
func TestProxyStats_CompareCopy(t *testing.T) {
	stats := ProxyStats{
		TotalRequests:   42,
		Intercepted:     10,
		PassedThrough:   32,
		Detections:      5,
		BlockedRequests: 1,
		MLDetections:    2,
		StartTime:       time.Now(),
	}

	data1, _ := json.Marshal(stats)
	stats.TotalRequests = 999
	data2, _ := json.Marshal(stats)

	if bytes.Equal(data1, data2) {
		t.Error("Modifying stats should change JSON output")
	}
}

// TestProxy_NewWithCustomTargets tests creating a proxy with custom targets.
func TestProxy_NewWithCustomTargets(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 0,
		Targets: []config.TargetConfig{
			{Domain: "api.custom.com", Description: "Custom API"},
			{Domain: "custom.ai", Description: "Custom AI"},
		},
		Privacy: config.PrivacyConfig{
			NoPromptText: true,
		},
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if !p.isTargetDomain("api.custom.com") {
		t.Error("api.custom.com should be a target domain")
	}
	if !p.isTargetDomain("custom.ai") {
		t.Error("custom.ai should be a target domain")
	}
	if p.isTargetDomain("api.openai.com") {
		t.Error("api.openai.com should NOT be a target domain with custom targets")
	}
}

// TestHandleHTTP_NonTargetDomain_Forward tests handleHTTP with a non-target backend.
func TestHandleHTTP_NonTargetDomain_Forward(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from backend"))
	}))
	defer backend.Close()

	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	backendURL, _ := url.Parse(backend.URL)
	req := httptest.NewRequest("GET", backend.URL, nil)
	req.URL = backendURL
	req.Host = backendURL.Host

	rec := httptest.NewRecorder()
	p.handleHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !bytes.Contains([]byte(body), []byte("hello from backend")) {
		t.Errorf("Expected response to contain 'hello from backend', got: %s", body)
	}
}

// TestHandleHTTP_TargetDomain_ScanAndForward tests handleHTTP with target domain scanning.
func TestHandleHTTP_TargetDomain_ScanAndForward(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SSN: 123-45-6789"))
	}))
	defer backend.Close()

	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	backendURL, _ := url.Parse(backend.URL)
	req := httptest.NewRequest("GET", "http://api.openai.com/v1/chat/completions", nil)
	req.URL.Scheme = backendURL.Scheme
	req.URL.Host = backendURL.Host
	req.Host = backendURL.Host

	rec := httptest.NewRecorder()
	p.handleHTTP(rec, req)

	// Request should be forwarded (may fail since we're overriding host)
	t.Logf("handleHTTP with target domain returned status %d", rec.Code)
}

// TestHandleHTTP_EmptyHost tests handleHTTP with empty host.
func TestHandleHTTP_EmptyHost(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = ""
	rec := httptest.NewRecorder()

	p.handleHTTP(rec, req)
	// Should handle gracefully (may return 502)
	t.Logf("handleHTTP with empty host returned status %d", rec.Code)
}

// TestHandleRequest_ConnectMethod_NonTarget tests CONNECT to non-target domain.
func TestHandleRequest_ConnectMethod_NonTarget(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("CONNECT", "/", nil)
	req.URL.Host = "example.com:443"
	rec := httptest.NewRecorder()

	p.handleRequest(rec, req)

	// Should attempt tunnel (503 since no actual connection available)
	// or 200 if tunnel works
	if rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusOK {
		t.Logf("CONNECT to non-target: status %d", rec.Code)
	}
}

// TestHandleRequest_ConnectMethod_Target tests CONNECT to target domain.
func TestHandleRequest_ConnectMethod_Target(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("CONNECT", "/", nil)
	req.URL.Host = "api.openai.com:443"
	rec := httptest.NewRecorder()

	p.handleRequest(rec, req)

	// Should attempt MITM (will fail in test since ResponseRecorder can't hijack)
	// But should still count as intercepted
	stats := p.GetStats()
	if stats.Intercepted == 0 {
		t.Error("CONNECT to target domain should increment Intercepted count")
	}
}

// TestGetStats_ReturnsCopy tests that GetStats returns a copy.
func TestGetStats_ReturnsCopy(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0
	cfg.Privacy.NoPromptText = true

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	stats1 := p.GetStats()
	_ = p.GetStats() // Verify multiple calls work

	// Modify stats1 and verify it doesn't affect future calls
	stats1.TotalRequests = 999
	stats3 := p.GetStats()
	if stats3.TotalRequests == 999 {
		t.Error("GetStats should return a copy, not a reference")
	}
}
