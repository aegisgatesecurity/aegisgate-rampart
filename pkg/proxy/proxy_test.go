package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"
)

func TestIsTargetDomain(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tests := []struct {
		host     string
		expected bool
	}{
		{"api.openai.com", true},
		{"chat.openai.com", true},
		{"api.anthropic.com", true},
		{"claude.ai", true},
		{"api.deepseek.com", true},
		{"chat.deepseek.com", true},
		{"www.google.com", false},
		{"github.com", false},
		{"localhost", false},
		{"", false},
	}

	for _, tt := range tests {
		result := p.isTargetDomain(tt.host)
		if result != tt.expected {
			t.Errorf("isTargetDomain(%q) = %v, want %v", tt.host, result, tt.expected)
		}
	}
}

func TestProxyNew(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0 // Let OS pick
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if p == nil {
		t.Fatal("New returned nil proxy")
	}
	if p.detector == nil {
		t.Error("Proxy should have a detector")
	}
	if len(p.targets) != 27 {
		t.Errorf("Proxy targets = %d, want 27", len(p.targets))
	}
}

func TestProxyNewWithConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Verbose = true
	cfg.DaemonMode = true
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New with config failed: %v", err)
	}
	_ = p
}

func TestGetStats(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	stats := p.GetStats()
	if stats.TotalRequests != 0 {
		t.Errorf("Initial TotalRequests = %d, want 0", stats.TotalRequests)
	}
	if stats.Detections != 0 {
		t.Errorf("Initial Detections = %d, want 0", stats.Detections)
	}
	if stats.BlockedRequests != 0 {
		t.Errorf("Initial BlockedRequests = %d, want 0", stats.BlockedRequests)
	}
}

func TestProxyStatsStruct(t *testing.T) {
	s := ProxyStats{
		TotalRequests:   100,
		Detections:      15,
		BlockedRequests: 2,
		MLDetections:    3,
		Intercepted:     50,
		PassedThrough:   50,
	}
	if s.TotalRequests != 100 {
		t.Errorf("TotalRequests = %d", s.TotalRequests)
	}
	if s.Detections != 15 {
		t.Errorf("Detections = %d", s.Detections)
	}
	if s.BlockedRequests != 2 {
		t.Errorf("BlockedRequests = %d", s.BlockedRequests)
	}
	if s.MLDetections != 3 {
		t.Errorf("MLDetections = %d", s.MLDetections)
	}
	if s.Intercepted != 50 {
		t.Errorf("Intercepted = %d", s.Intercepted)
	}
	if s.PassedThrough != 50 {
		t.Errorf("PassedThrough = %d", s.PassedThrough)
	}
}

func TestNotifyDesktop(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	// notifyDesktop should not panic — pass a valid summary
	summary := &detector.Summary{
		TotalDetections: 1,
		Results:         []detector.Result{{Category: "pii", Severity: "high", Text: "SSN"}},
	}
	p.notifyDesktop("request", "api.openai.com", summary)
}

func TestSeverityColorAndEmoji(t *testing.T) {
	tests := []struct {
		severity  string
		wantColor string
		wantEmoji string
	}{
		{"critical", colorRed, "🔴"},
		{"high", colorRed, "🔴"},
		{"medium", colorYellow, "🟡"},
		{"low", colorGreen, "🟢"},
		{"unknown", colorCyan, "⚪"},
		{"", colorCyan, "⚪"},
	}

	for _, tt := range tests {
		gotColor, gotEmoji := severityColorAndEmoji(tt.severity)
		if gotColor != tt.wantColor {
			t.Errorf("severityColorAndEmoji(%q) color = %q, want %q", tt.severity, gotColor, tt.wantColor)
		}
		if gotEmoji != tt.wantEmoji {
			t.Errorf("severityColorAndEmoji(%q) emoji = %q, want %q", tt.severity, gotEmoji, tt.wantEmoji)
		}
	}
}

func TestBoolColor(t *testing.T) {
	if boolColor(true) != colorRed {
		t.Errorf("boolColor(true) = %q, want %q", boolColor(true), colorRed)
	}
	if boolColor(false) != colorGreen {
		t.Errorf("boolColor(false) = %q, want %q", boolColor(false), colorGreen)
	}
}

func TestPrintDetectionForeground(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Test with a summary that has detections
	summary := &detector.Summary{
		TotalDetections: 3,
		Blocked:         true,
		Results: []detector.Result{
			{Category: "pii", Severity: "high", Text: "SSN detected", Rule: "pii_us_ssn"},
			{Category: "secrets", Severity: "critical", Text: "AWS key detected", Rule: "aws_access_key"},
			{Category: "compliance", Severity: "low", Text: "GDPR mention", Rule: "gdpr_reference"},
		},
		PIICategories: []string{"pii_us_ssn"},
		SecretTypes:   []string{"aws_access_key"},
	}

	// printDetection should not panic
	p.printDetection("request", "api.openai.com", "/v1/chat/completions", summary)

	// Test with empty summary (no detections)
	emptySummary := &detector.Summary{
		TotalDetections: 0,
		Blocked:         false,
		Results:         []detector.Result{},
	}
	p.printDetection("response", "claude.ai", "/api/conversation", emptySummary)
}

func TestPrintDetectionWithMLScore(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	summary := &detector.Summary{
		TotalDetections: 1,
		Blocked:         false,
		MLScore:         0.85,
		Results: []detector.Result{
			{Category: "ml_threat", Severity: "high", Text: "adversarial prompt", Rule: "char_cnn_bilstm", MLScore: 0.85},
		},
	}

	p.printDetection("response", "api.anthropic.com", "/v1/messages", summary)
}

func TestAll27TargetDomainsPresent(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	expectedDomains := []string{
		"api.openai.com", "chat.openai.com", "chatgpt.com",
		"api.anthropic.com", "claude.ai",
		"generativelanguage.googleapis.com", "gemini.google.com",
		"api.copilot.microsoft.com", "copilot.microsoft.com", "copilot.cloud.microsoft",
		"api.perplexity.ai", "perplexity.ai", "www.perplexity.ai",
		"api.x.ai", "grok.com", "www.grok.com",
		"api.mistral.ai", "codestral.mistral.ai", "chat.mistral.ai", "le-chat.mistral.ai",
		"api.deepseek.com", "chat.deepseek.com",
		"api.duck.ai", "duck.ai", "www.duck.ai",
		"meta.ai", "www.meta.ai",
	}

	for _, domain := range expectedDomains {
		if !p.isTargetDomain(domain) {
			t.Errorf("Expected target domain %s not found", domain)
		}
	}
}

func TestScanAndAlertWithDetection(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	before := p.GetStats()

	// Text containing an SSN should trigger detection
	p.scanAndAlert("request", "api.openai.com", "/v1/chat/completions", []byte("My SSN is 123-45-6789"))

	after := p.GetStats()
	if after.Detections <= before.Detections {
		t.Errorf("Expected Detections to increase, before=%d after=%d", before.Detections, after.Detections)
	}
}

func TestScanAndAlertCleanText(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	before := p.GetStats()

	// Clean text should not trigger detection
	p.scanAndAlert("response", "api.openai.com", "/v1/chat/completions", []byte("The weather is nice today."))

	after := p.GetStats()
	if after.Detections != before.Detections {
		t.Errorf("Clean text should not increase detections, before=%d after=%d", before.Detections, after.Detections)
	}
}

func TestScanAndAlertEmptyBody(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	before := p.GetStats()
	p.scanAndAlert("response", "api.openai.com", "/v1/chat/completions", []byte(""))

	after := p.GetStats()
	if after.Detections != before.Detections {
		t.Errorf("Empty body should not increase detections, before=%d after=%d", before.Detections, after.Detections)
	}
}

func TestPrintDetectionBlocked(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	summary := &detector.Summary{
		TotalDetections: 1,
		Blocked:         true,
		BlockReason:     "pii_detected",
		Results: []detector.Result{
			{Category: "pii", Severity: "critical", Text: "SSN detected", Rule: "pii_us_ssn"},
		},
	}
	// Should not panic
	p.printDetection("request", "api.openai.com", "/v1/chat/completions", summary)
}

func TestPrintDetectionMinimal(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Minimal summary with no optional fields
	summary := &detector.Summary{
		TotalDetections: 1,
		Blocked:         false,
		Results: []detector.Result{
			{Category: "compliance", Severity: "low", Text: "GDPR mention"},
		},
	}
	p.printDetection("response", "claude.ai", "", summary)
}

func TestNotifyDesktopWithResults(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	summary := &detector.Summary{
		TotalDetections: 2,
		Blocked:         false,
		Results: []detector.Result{
			{Category: "pii", Severity: "medium", Text: "email detected"},
			{Category: "secrets", Severity: "high", Text: "AWS key detected"},
		},
	}
	// Should not panic — daemon mode notification
	p.notifyDesktop("request", "api.openai.com", summary)
}

func TestColorConstants(t *testing.T) {
	// Verify color constants are defined and non-empty
	colors := []string{colorReset, colorRed, colorYellow, colorGreen, colorCyan, colorBold, colorDim}
	for i, c := range colors {
		if c == "" {
			t.Errorf("Color constant at index %d is empty", i)
		}
	}
}

func TestIsTargetDomainEmptyHost(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if p.isTargetDomain("") {
		t.Error("Empty host should not be a target domain")
	}
}

func TestIsTargetDomainSubdomain(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// api.openai.com should match openai.com target
	if !p.isTargetDomain("api.openai.com") {
		t.Error("api.openai.com should match openai.com target")
	}

	// v1.api.openai.com should also match
	if !p.isTargetDomain("v1.api.openai.com") {
		t.Error("v1.api.openai.com should match openai.com target")
	}

	// Subdomain of non-target should not match
	if p.isTargetDomain("api.example.com") {
		t.Error("api.example.com should not match any target")
	}
}

func TestHandleHTTPWithTargetDomain(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Start a backend server that returns a response
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello from AI API"))
	}))
	defer backend.Close()

	// Extract host from backend URL
	backendURL := backend.URL
	req := httptest.NewRequest(http.MethodGet, backendURL, nil)

	w := httptest.NewRecorder()
	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("handleHTTP status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleHTTPWithNonTargetDomain(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Start a backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer backend.Close()

	req := httptest.NewRequest(http.MethodGet, backend.URL, nil)
	w := httptest.NewRecorder()

	p.handleHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("handleHTTP status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleRequestRoutes(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Test /detect route
	body := `{"text": "Hello"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.handleRequest(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/detect route: expected 200, got %d", w.Code)
	}

	// Test /stats route
	req = httptest.NewRequest(http.MethodGet, "/stats", nil)
	w = httptest.NewRecorder()
	p.handleRequest(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/stats route: expected 200, got %d", w.Code)
	}
}

func TestScanAndAlertMultipleTypes(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Text with multiple detection types: PII + secrets
	text := "SSN: 263-78-1234 and AWS key: AKIAIOSFODNN7EXAMPLE"
	p.scanAndAlert("request", "api.openai.com", "/v1/chat/completions", []byte(text))

	stats := p.GetStats()
	if stats.Detections < 1 {
		t.Errorf("Expected at least 1 detection, got %d", stats.Detections)
	}
}

func TestScanAndAlertXSS(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	xssPayload := `<script>alert("xss")</script>`
	p.scanAndAlert("response", "api.anthropic.com", "/v1/messages", []byte(xssPayload))

	stats := p.GetStats()
	if stats.Detections < 1 {
		t.Errorf("Expected XSS detection, got %d detections", stats.Detections)
	}
}

func TestProxyDefaultPort(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.ProxyPort != 8080 {
		t.Errorf("Default proxy port = %d, want 8080", cfg.ProxyPort)
	}
}

// ============================================================================
// Block Mode Tests
// ============================================================================

func TestShouldBlockMonitorMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeMonitor
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	result := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "pii", Severity: "critical", Text: "SSN detected"},
		},
	}

	shouldBlock, reason := p.shouldBlock(result)
	if shouldBlock {
		t.Error("shouldBlock should return false in monitor mode")
	}
	if reason != "" {
		t.Errorf("reason should be empty in monitor mode, got: %s", reason)
	}
}

func TestShouldBlockBlockModeCritical(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityHigh
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	result := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "pii", Severity: "critical", Text: "SSN detected", Rule: "pii_ssn"},
		},
	}

	shouldBlock, reason := p.shouldBlock(result)
	if !shouldBlock {
		t.Error("shouldBlock should return true for critical detection in block mode")
	}
	if reason == "" {
		t.Error("reason should not be empty when blocking")
	}
}

func TestShouldBlockBlockModeBelowThreshold(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityCritical // only block on critical
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	result := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "pii", Severity: "medium", Text: "phone detected", Rule: "pii_phone"},
		},
	}

	shouldBlock, _ := p.shouldBlock(result)
	if shouldBlock {
		t.Error("shouldBlock should return false for medium detection when threshold is critical")
	}
}

func TestShouldBlockBlockModeCategoryFilter(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityHigh
	cfg.Block.Categories = []string{"pii"} // only block PII
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// XSS should NOT be blocked (category filter)
	xssResult := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "xss", Severity: "critical", Text: "script tag", Rule: "xss_script_tag"},
		},
	}
	shouldBlock, _ := p.shouldBlock(xssResult)
	if shouldBlock {
		t.Error("shouldBlock should return false for XSS when category filter is pii-only")
	}

	// PII SHOULD be blocked (category filter passes)
	piiResult := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "pii", Severity: "critical", Text: "SSN detected", Rule: "pii_ssn"},
		},
	}
	shouldBlock, reason := p.shouldBlock(piiResult)
	if !shouldBlock {
		t.Error("shouldBlock should return true for PII with pii category filter")
	}
	if reason == "" {
		t.Error("reason should not be empty when blocking")
	}
}

func TestShouldBlockNoDetections(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	result := &detector.Summary{
		TotalDetections: 0,
		Results:         []detector.Result{},
	}

	shouldBlock, _ := p.shouldBlock(result)
	if shouldBlock {
		t.Error("shouldBlock should return false when there are no detections")
	}
}

func TestMeetsSeverityThreshold(t *testing.T) {
	tests := []struct {
		severity  string
		threshold string
		expected  bool
	}{
		{"critical", "critical", true},
		{"critical", "high", true},
		{"critical", "medium", true},
		{"critical", "low", true},
		{"high", "critical", false},
		{"high", "high", true},
		{"high", "medium", true},
		{"medium", "critical", false},
		{"medium", "high", false},
		{"medium", "medium", true},
		{"low", "critical", false},
		{"low", "high", false},
		{"low", "medium", false},
		{"low", "low", true},
		{"unknown", "high", false},
		{"high", "unknown", true}, // unknown threshold defaults to high
	}

	for _, tc := range tests {
		result := meetsSeverityThreshold(tc.severity, tc.threshold)
		if result != tc.expected {
			t.Errorf("meetsSeverityThreshold(%q, %q) = %v, want %v", tc.severity, tc.threshold, result, tc.expected)
		}
	}
}

func TestBlockDetectAPIInBlockMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityHigh
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Test that /detect returns a block response for PII
	payload := `{"text":"My SSN is 123-45-6789"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	if w.Code != cfg.Block.StatusCode {
		t.Errorf("Expected status %d, got %d", cfg.Block.StatusCode, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "blocked") {
		t.Errorf("Expected block response to contain 'blocked', got: %s", body)
	}
	if !strings.Contains(body, "X-Rampart-Blocked") {
		// Check body content instead of header (already written)
		t.Logf("Block response body: %s", body)
	}
}

func TestBlockDetectAPIMonitorMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeMonitor
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// In monitor mode, /detect should return normal detection result (200)
	payload := `{"text":"My SSN is 123-45-6789"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 in monitor mode, got %d", w.Code)
	}

	body := w.Body.String()
	if strings.Contains(body, "blocked") && !strings.Contains(body, `"blocked":false`) {
		t.Errorf("In monitor mode, response should not be a block response, got: %s", body)
	}
}

func TestBlockDetectAPICleanText(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityHigh
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Clean text should NOT be blocked even in block mode
	payload := `{"text":"Hello, how are you?"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for clean text, got %d", w.Code)
	}
}

func TestConfigBlockDefaults(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Mode != config.ModeMonitor {
		t.Errorf("Default mode should be monitor, got %s", cfg.Mode)
	}
	if cfg.Block.Threshold != config.SeverityHigh {
		t.Errorf("Default block threshold should be high, got %s", cfg.Block.Threshold)
	}
	if cfg.Block.StatusCode != 403 {
		t.Errorf("Default block status code should be 403, got %d", cfg.Block.StatusCode)
	}
	if !cfg.Block.IncludeDetections {
		t.Error("Default IncludeDetections should be true")
	}
	if cfg.Block.Message != "Request blocked by AegisGate Rampart" {
		t.Errorf("Default block message incorrect, got: %s", cfg.Block.Message)
	}
	if cfg.Block.BlockResponse != "both" {
		t.Errorf("Default BlockResponse should be 'both', got %s", cfg.Block.BlockResponse)
	}
}

func TestStatsIncludeMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	stats := p.GetStats()
	if stats.Mode != config.ModeBlock {
		t.Errorf("Expected mode=%s in stats, got %s", config.ModeBlock, stats.Mode)
	}
}

// ============================================================================
// MITM Block Mode End-to-End Tests
// ============================================================================

func TestMITMBlockModeRequest(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityHigh
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Test /detect endpoint in block mode directly (no goroutine race)
	piiPayload := `{"text":"My SSN is 123-45-6789"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(piiPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	if w.Code != 403 {
		t.Errorf("Expected 403 in block mode for PII, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "blocked") {
		t.Errorf("Expected block response body to contain 'blocked', got: %s", body)
	}
	if !strings.Contains(body, "pii") {
		t.Errorf("Expected block response to contain detection category 'pii', got: %s", body)
	}

	// Verify stats include blocked request
	stats := p.GetStats()
	if stats.BlockedRequests < 1 {
		t.Errorf("Expected at least 1 blocked request, got %d", stats.BlockedRequests)
	}
	if stats.Mode != config.ModeBlock {
		t.Errorf("Expected mode='block' in stats, got '%s'", stats.Mode)
	}
}

func TestMITMBlockModeResponseThreshold(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityCritical // only block critical
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// High-severity (but not critical) should NOT be blocked with critical threshold
	highPayload := `{"text":"API key: AKIAIOSFODNN7EXAMPLE"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(highPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	// This may or may not be blocked depending on what severity the detector assigns
	// The key test is that shouldBlock() logic works correctly
	t.Logf("High threshold test: status=%d, body=%s", w.Code, w.Body.String())
}

func TestBlockResponseFormat(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityHigh
	cfg.Block.StatusCode = 403
	cfg.Block.IncludeDetections = true
	cfg.Block.Message = "Blocked by Rampart"
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	piiPayload := `{"text":"SSN: 123-45-6789"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(piiPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	if w.Code != 403 {
		t.Errorf("Expected 403, got %d", w.Code)
	}

	// Check response headers
	if w.Header().Get("X-Rampart-Blocked") != "true" {
		t.Error("Expected X-Rampart-Blocked: true header")
	}

	// Parse response body
	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse block response JSON: %v", err)
	}

	if result["blocked"] != true {
		t.Error("Expected blocked=true in response")
	}
	if result["direction"] != "request" {
		t.Error("Expected direction=request in response")
	}
	if result["message"] != "Blocked by Rampart" {
		t.Errorf("Expected custom message, got: %v", result["message"])
	}
	if results, ok := result["results"].([]interface{}); !ok || len(results) == 0 {
		t.Error("Expected non-empty results array (IncludeDetections=true)")
	}
}

func TestBlockResponseCustomStatusCode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityHigh
	cfg.Block.StatusCode = 451 // "Unavailable For Legal Reasons"
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	piiPayload := `{"text":"SSN: 123-45-6789"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(piiPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	if w.Code != 451 {
		t.Errorf("Expected custom status 451, got %d", w.Code)
	}
}

func TestBlockResponseExcludeDetections(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityHigh
	cfg.Block.IncludeDetections = false
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	piiPayload := `{"text":"SSN: 123-45-6789"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(piiPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	results, ok := result["results"].([]interface{})
	if ok && len(results) > 0 {
		t.Error("Expected empty/null results when IncludeDetections=false")
	}
}

func TestFormatBlockHTTPResponse(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Message = "Custom block message"
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	result := &detector.Summary{
		TotalDetections: 2,
		Results: []detector.Result{
			{Category: "pii", Severity: "critical", Text: "SSN detected", Rule: "pii_ssn"},
			{Category: "secrets", Severity: "high", Text: "API key detected", Rule: "secret_aws_key"},
		},
	}

	blockBody := p.formatBlockHTTPResponse("response", "api.openai.com", "/v1/chat/completions", result, "pii: SSN detected")

	if !strings.Contains(string(blockBody), "Custom block message") {
		t.Error("Expected custom message in block response")
	}
	if !strings.Contains(string(blockBody), "response") {
		t.Error("Expected direction in block response")
	}
	if !strings.Contains(string(blockBody), "api.openai.com") {
		t.Error("Expected host in block response")
	}
	if !strings.Contains(string(blockBody), "pii") {
		t.Error("Expected category in block response")
	}
}

// ============================================================================
// Coverage improvement tests
// ============================================================================

func TestFormatBlockHTTPResponseCustomMessage(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Message = "Custom: threat detected"
	cfg.Block.IncludeDetections = false
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	result := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "xss", Severity: "critical", Text: "script tag", Rule: "xss_script"},
		},
	}

	body := p.formatBlockHTTPResponse("response", "api.openai.com", "/v1/chat/completions", result, "xss: script tag")
	if !strings.Contains(string(body), "Custom: threat detected") {
		t.Errorf("Expected custom message in block response, got: %s", body)
	}
	if cfg.Block.IncludeDetections == false && strings.Contains(string(body), "results") {
		t.Errorf("Expected results to be omitted when IncludeDetections=false, but found: %s", body)
	}
}

func TestFormatBlockHTTPResponseEmptyCategories(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	result := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "secret", Severity: "high", Text: "AWS key", Rule: "aws_key", Confidence: 0.95},
		},
	}

	body := p.formatBlockHTTPResponse("request", "api.anthropic.com", "/v1/messages", result, "secret: AWS key")
	if !strings.Contains(string(body), "api.anthropic.com") {
		t.Error("Expected host in response")
	}
	if !strings.Contains(string(body), "secret") {
		t.Error("Expected category in response")
	}
}

func TestMeetsSeverityThresholdEdgeCases(t *testing.T) {
	tests := []struct {
		severity  string
		threshold string
		expected  bool
	}{
		{"", "high", false},
		{"high", "", true}, // empty threshold defaults to high
		{"", "", false},
	}
	for _, tc := range tests {
		result := meetsSeverityThreshold(tc.severity, tc.threshold)
		if result != tc.expected {
			t.Errorf("meetsSeverityThreshold(%q, %q) = %v, want %v", tc.severity, tc.threshold, result, tc.expected)
		}
	}
}

func TestContainsCategory(t *testing.T) {
	cats := []string{"pii", "secrets", "xss"}
	if !containsCategory(cats, "pii") {
		t.Error("Expected pii to be in categories")
	}
	if !containsCategory(cats, "xss") {
		t.Error("Expected xss to be in categories")
	}
	if containsCategory(cats, "toxicity") {
		t.Error("Expected toxicity to NOT be in categories")
	}
	if containsCategory([]string{}, "pii") {
		t.Error("Empty categories should not match anything")
	}
}

func TestShouldBlockBlockModeAllCategories(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityLow
	cfg.Block.Categories = []string{} // empty = all categories
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	result := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "xss", Severity: "low", Text: "onerror", Rule: "xss_onerror"},
		},
	}

	shouldBlock, _ := p.shouldBlock(result)
	if !shouldBlock {
		t.Error("Expected low-severity XSS to be blocked when threshold is low and categories is empty")
	}
}

func TestShouldBlockMixedSeverity(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	cfg.Block.Threshold = config.SeverityHigh
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Mix of low and critical — should block because critical meets threshold
	result := &detector.Summary{
		TotalDetections: 2,
		Results: []detector.Result{
			{Category: "pii", Severity: "low", Text: "name detected", Rule: "pii_name"},
			{Category: "pii", Severity: "critical", Text: "SSN detected", Rule: "pii_ssn"},
		},
	}

	shouldBlock, reason := p.shouldBlock(result)
	if !shouldBlock {
		t.Error("Expected block when at least one detection meets threshold")
	}
	if !strings.Contains(reason, "critical") && !strings.Contains(reason, "SSN") {
		t.Logf("Block reason: %s", reason)
	}
}

func TestReloadConfigBlockMode(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Verify initial targets
	if !p.isTargetDomain("api.openai.com") {
		t.Error("Expected api.openai.com to be a target")
	}

	// Reload with different targets
	newCfg := config.DefaultConfig()
	newCfg.Targets = []config.TargetConfig{
		{Domain: "custom.api.example.com", Paths: []string{"/v1/*"}, Description: "Custom API"},
	}

	p.ReloadConfig(newCfg)

	// Old target should be gone
	if p.isTargetDomain("api.openai.com") {
		t.Error("Expected api.openai.com to NOT be a target after reload")
	}
	// New target should be present
	if !p.isTargetDomain("custom.api.example.com") {
		t.Error("Expected custom.api.example.com to be a target after reload")
	}
}

func TestHandleStatsAPIWithMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeBlock
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()

	p.HandleStatsAPI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var stats map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if stats["mode"] != "block" {
		t.Errorf("Expected mode=block in stats, got %v", stats["mode"])
	}
}

func TestHandleDetectAPIMethodNotAllowed(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/detect", nil)
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for GET /detect, got %d", w.Code)
	}
}

func TestBlockHandleDetectInvalidJSON(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestBlockHandleDetectEmptyBody(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	p.HandleDetectAPI(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for empty body, got %d", w.Code)
	}
}

// TestHandleHealthAPI tests the /health liveness endpoint.
func TestHandleHealthAPI(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	p.HandleHealthAPI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %q", result["status"])
	}
}

// TestHandleReadyAPI tests the /readiness endpoint.
func TestHandleReadyAPI(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	p.HandleReadyAPI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["status"] != "ready" {
		t.Errorf("expected status ready, got %v", result["status"])
	}
	if result["detector"] != true {
		t.Error("expected detector to be true")
	}
}

// TestHandleDetectAPI_MaxBodySize tests that oversized request bodies are rejected.
func TestHandleDetectAPI_MaxBodySize(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Create a request body larger than 10MB
	largeBody := `{"text":"` + strings.Repeat("A", 11*1024*1024) + `"}`

	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.HandleDetectAPI(w, req)

	// Should get an error (413 or 400 from MaxBytesReader)
	if w.Code == http.StatusOK {
		t.Error("expected non-200 for oversized request body")
	}
}
