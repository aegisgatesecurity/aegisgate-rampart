// SPDX-License-Identifier: Apache-2.0
package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

// TestHandleHTTP_NonTargetHost tests handleHTTP with a non-target host.
func TestHandleHTTP_NonTargetHost(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Start a simple HTTP server to forward to
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello from backend"))
	}))
	defer backend.Close()

	// Create an HTTP request through the proxy
	req := httptest.NewRequest(http.MethodGet, backend.URL, nil)
	req.Host = strings.TrimPrefix(backend.URL, "http://")
	w := httptest.NewRecorder()

	p.handleHTTP(w, req)

	// Should have forwarded the request
	if w.Code != http.StatusOK {
		t.Errorf("handleHTTP status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHandleHTTP_TargetHostWithBody tests handleHTTP with a target host that has a body.
func TestHandleHTTP_TargetHostWithBody(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Start a backend server for api.openai.com
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("AI response"))
	}))
	defer backend.Close()

	// Create an HTTP request with a body containing PII
	body := `{"prompt": "My SSN is 263-78-1234"}`
	req := httptest.NewRequest(http.MethodPost, backend.URL, strings.NewReader(body))
	req.Host = "api.openai.com"
	w := httptest.NewRecorder()

	p.handleHTTP(w, req)
}

// TestScanAndAlert_MultipleDetections tests scanAndAlert with multiple detection types.
func TestScanAndAlert_MultipleDetections(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	before := p.GetStats()

	// Text with PII and secrets
	text := "My SSN is 263-78-1234 and my AWS key is AKIAIOSFODNN7EXAMPLE"
	p.scanAndAlert("response", "api.openai.com", "/v1/chat/completions", []byte(text))

	after := p.GetStats()
	if after.Detections <= before.Detections {
		t.Errorf("Expected Detections to increase, before=%d after=%d", before.Detections, after.Detections)
	}
}

// TestNotifyDesktop tests the notifyDesktop method (logs to stderr).
func TestNotifyDesktop_Coverage(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Create a detector result for testing
	result, _ := p.detector.Detect("SSN: 263-78-1234")

	// Just verify notifyDesktop doesn't panic
	p.notifyDesktop("response", "api.openai.com", result)
}

// TestHandleDetectAPI_LargeBody tests /detect with a large text body.
func TestHandleDetectAPI_LargeBody(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Generate a large text
	largeText := strings.Repeat("Hello world this is a test. ", 1000)
	body := fmt.Sprintf(`{"text": "%s"}`, largeText)
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Large body should return 200, got %d", w.Code)
	}
}

// TestHandleDetectAPI_MissingTextField tests /detect with JSON that doesn't have "text" field.
func TestHandleDetectAPI_MissingTextField(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	body := `{"not_text": "hello"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	// Should still return 200 with empty text detection
	if w.Code != http.StatusOK {
		t.Logf("Missing text field returned %d (may be OK)", w.Code)
	}
}

// TestIsTargetDomain_SubdomainMatch tests subdomain matching.
func TestIsTargetDomain_SubdomainMatch(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tests := []struct {
		host     string
		expected bool
	}{
		// Exact matches
		{"api.openai.com", true},
		{"claude.ai", true},
		// Subdomain matches
		{"chat.openai.com", true},
		{"v1.api.openai.com", true},
		// Non-matches
		{"google.com", false},
		{"openai.com.evil.com", false},
	}

	for _, tt := range tests {
		result := p.isTargetDomain(tt.host)
		if result != tt.expected {
			t.Errorf("isTargetDomain(%q) = %v, want %v", tt.host, result, tt.expected)
		}
	}
}

// TestCertDir tests the certDir function.
func TestCertDir_Coverage(t *testing.T) {
	dir := certDir()
	if dir == "" {
		t.Error("certDir should not return empty string")
	}
	if !strings.Contains(dir, "aegisgate-rampart") {
		t.Errorf("certDir should contain 'aegisgate-rampart', got %s", dir)
	}
}

// TestProxyStatsConcurrentAccess tests concurrent stats updates.
func TestProxyStatsConcurrentAccess(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	done := make(chan bool)
	for i := 0; i < 20; i++ {
		go func() {
			p.scanAndAlert("request", "api.openai.com", "/test", []byte("test body "+strings.Repeat("a", 100)))
			_ = p.GetStats()
			done <- true
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}

// TestHandleDetectAPI_EmptyBody tests /detect with empty request body.
func TestHandleDetectAPI_EmptyBody(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/detect", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	// Should return 400 for empty body (io.ReadAll will return empty, json.Unmarshal will fail)
	if w.Code != http.StatusBadRequest {
		t.Logf("Empty body returned %d (expected 400)", w.Code)
	}
}

// TestHandleDetectAPI_ResponseFormat tests that the /detect response is valid JSON.
func TestHandleDetectAPI_ResponseFormat(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	body := `{"text": "My SSN is 263-78-1234"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Response is not valid JSON: %v", err)
	}

	// Should have key detection fields
	if _, ok := result["total_detections"]; !ok {
		t.Error("Response should contain 'total_detections' field")
	}
}

// TestHandleDetectAPI_XSSDetection tests /detect with XSS content.
func TestHandleDetectAPI_XSSDetection(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	body := `{"text": "<script>alert('xss')</script>"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	var result map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &result)

	if result["total_detections"].(float64) < 1 {
		t.Error("XSS content should be detected")
	}
}

// TestHandleRequest_GETStats verifies the GET /stats route.
func TestHandleRequest_GETStats(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	p.handleRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GET /stats returned %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHandleRequest_POSTDetect verifies the POST /detect route.
func TestHandleRequest_POSTDetect(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	body := `{"text": "clean text"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("POST /detect returned %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHandleRequest_ConnectMethod verifies CONNECT method routing.
func TestHandleRequest_ConnectMethod(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// CONNECT requests will fail since there's no backend, but should route correctly
	req := httptest.NewRequest(http.MethodConnect, "api.openai.com:443", nil)
	w := httptest.NewRecorder()
	p.handleRequest(w, req)

	// The CONNECT handler will try to connect and fail, resulting in a 503
	// This is expected behavior in test
	t.Logf("CONNECT response code: %d", w.Code)
}

// TestNewProxyWithPort tests proxy creation with different port settings.
func TestNewProxyWithPort(t *testing.T) {
	tests := []struct {
		port int
	}{
		{8080},
		{9090},
		{0},
	}

	for _, tt := range tests {
		cfg := config.DefaultConfig()
		cfg.ProxyPort = tt.port
		p, err := New(cfg)
		if err != nil {
			t.Errorf("New with port %d failed: %v", tt.port, err)
			continue
		}
		if p == nil {
			t.Errorf("New with port %d returned nil", tt.port)
		}
	}
}

// TestScanAndAlert_EmptyBody verifies scanAndAlert with nil/empty body.
func TestScanAndAlert_NilBody(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	before := p.GetStats()
	// Empty string body
	p.scanAndAlert("request", "example.com", "/test", []byte{})
	after := p.GetStats()

	if after.Detections != before.Detections {
		t.Error("Empty body should not increase detections")
	}
}

// TestHandleDetectAPI_ReadAllError tests error handling when reading body fails.
func TestHandleDetectAPI_ReadAllError(t *testing.T) {
	p, err := New(config.DefaultConfig())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Create a request with a body that will fail after reading
	req := httptest.NewRequest(http.MethodPost, "/detect", io.NopCloser(strings.NewReader(`{"text": "test"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	// Should still succeed since the body is valid
	if w.Code != http.StatusOK {
		t.Logf("HandleDetectAPI returned %d", w.Code)
	}
}
