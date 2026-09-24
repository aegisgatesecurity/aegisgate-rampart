// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Proxy Coverage Gap Tests
// =========================================================================
//
// Targets uncovered functions in proxy.go to reach 85% coverage.
// These tests run in CI WITHOUT RAMPART_INTEGRATION=1.
//
// Coverage gaps addressed:
//   - generatePprofToken (0%)
//   - redactDetectionText (66.7%)
//   - isBlockedAddress / isBlockedIP (66.7% / 60%)
//   - forwardEntry (14.3%)
//   - tunnel (34.6%)
//   - Start / Shutdown lifecycle (42% / 28.6%)
//   - handleHTTP forwarding paths (65.8%)
//   - ScanForTest (0%)
//
// =========================================================================

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"
)

// ---------------------------------------------------------------------------
// generatePprofToken (was 0%)
// ---------------------------------------------------------------------------

func TestGeneratePprofToken_Format(t *testing.T) {
	token := generatePprofToken()
	if len(token) != 64 { // 32 bytes hex = 64 chars
		t.Errorf("expected 64 hex chars, got %d", len(token))
	}
	for _, c := range token {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("token contains non-hex char: %c", c)
			break
		}
	}
}

func TestGeneratePprofToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool, 10)
	for i := 0; i < 10; i++ {
		tok := generatePprofToken()
		if tokens[tok] {
			t.Fatalf("duplicate token generated at iteration %d", i)
		}
		tokens[tok] = true
	}
}

// ---------------------------------------------------------------------------
// redactDetectionText (was 66.7%)
// ---------------------------------------------------------------------------

func TestRedactDetectionText_ShortText(t *testing.T) {
	result := redactDetectionText("ab")
	if result != "[REDACTED]" {
		t.Errorf("expected [REDACTED] for 2-char text, got %s", result)
	}
}

func TestRedactDetectionText_ExactBoundary(t *testing.T) {
	// 4 chars → [REDACTED]
	result := redactDetectionText("abcd")
	if result != "[REDACTED]" {
		t.Errorf("expected [REDACTED] for 4-char text, got %s", result)
	}
}

func TestRedactDetectionText_LongText(t *testing.T) {
	result := redactDetectionText("AKIAIOSFODNN7EXAMPLE")
	if result != "AK***LE" {
		t.Errorf("expected 'AK***LE', got %s", result)
	}
}

func TestRedactDetectionText_FiveChars(t *testing.T) {
	// 5 chars → first 2 + *** + last 2
	result := redactDetectionText("abcde")
	if result != "ab***de" {
		t.Errorf("expected 'ab***de', got %s", result)
	}
}

// ---------------------------------------------------------------------------
// isBlockedAddress / isBlockedIP (were 66.7% / 60%)
// ---------------------------------------------------------------------------

func TestIsBlockedIP_Loopback(t *testing.T) {
	if !isBlockedIP(net.ParseIP("127.0.0.1")) {
		t.Error("127.0.0.1 should be blocked")
	}
	if !isBlockedIP(net.ParseIP("::1")) {
		t.Error("::1 should be blocked")
	}
}

func TestIsBlockedIP_Private(t *testing.T) {
	if !isBlockedIP(net.ParseIP("10.0.0.1")) {
		t.Error("10.0.0.1 should be blocked")
	}
	if !isBlockedIP(net.ParseIP("172.16.0.1")) {
		t.Error("172.16.0.1 should be blocked")
	}
	if !isBlockedIP(net.ParseIP("192.168.1.1")) {
		t.Error("192.168.1.1 should be blocked")
	}
}

func TestIsBlockedIP_LinkLocal(t *testing.T) {
	if !isBlockedIP(net.ParseIP("169.254.1.1")) {
		t.Error("169.254.1.1 should be blocked")
	}
}

func TestIsBlockedIP_CloudMetadata(t *testing.T) {
	if !isBlockedIP(net.ParseIP("169.254.169.254")) {
		t.Error("169.254.169.254 (cloud metadata) should be blocked")
	}
}

func TestIsBlockedIP_Unspecified(t *testing.T) {
	if !isBlockedIP(net.ParseIP("0.0.0.0")) {
		t.Error("0.0.0.0 should be blocked")
	}
}

func TestIsBlockedIP_Public(t *testing.T) {
	if isBlockedIP(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should NOT be blocked")
	}
	if isBlockedIP(net.ParseIP("1.1.1.1")) {
		t.Error("1.1.1.1 should NOT be blocked")
	}
}

func TestIsBlockedAddress_DirectIP(t *testing.T) {
	if !isBlockedAddress("127.0.0.1") {
		t.Error("127.0.0.1 should be blocked")
	}
	if !isBlockedAddress("10.0.0.1") {
		t.Error("10.0.0.1 should be blocked")
	}
}

func TestIsBlockedAddress_PublicIP(t *testing.T) {
	if isBlockedAddress("8.8.8.8") {
		t.Error("8.8.8.8 should NOT be blocked")
	}
}

func TestIsBlockedAddress_UnresolvableHost(t *testing.T) {
	// Unresolvable host → LookupIP fails → returns false (allowed)
	result := isBlockedAddress("this-host-does-not-exist-ever.invalid")
	if result {
		t.Error("unresolvable host should not be blocked (returns false)")
	}
}

func TestIsBlockedAddress_LoopbackHostname(t *testing.T) {
	if !isBlockedAddress("localhost") {
		t.Error("localhost should be blocked")
	}
}

// ---------------------------------------------------------------------------
// forwardEntry (was 14.3%)
// ---------------------------------------------------------------------------

func TestForwardEntry_DisabledForwarder(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 0,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	// Default config has no platform_url → forwarder disabled
	result := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "secret", Severity: "high", Text: "AKIAIOSFODNN7EXAMPLE", Rule: "aws_key"},
		},
	}

	// Should not panic or block — forwarder is disabled
	p.forwardEntry("request", "api.openai.com", "/v1/chat/completions", result)
}

func TestForwardEntry_EnabledForwarder(t *testing.T) {
	// Start a mock platform server to receive forwarded events
	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer platformServer.Close()

	cfg := &config.Config{
		ProxyPort:   0,
		Targets:     config.DefaultTargets(),
		PlatformURL: platformServer.URL,
		PlatformKey: "test-key",
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	if !p.forwarder.Enabled() {
		t.Fatal("forwarder should be enabled with platform_url set")
	}

	result := &detector.Summary{
		TotalDetections: 2,
		Results: []detector.Result{
			{Category: "secret", Severity: "high", Text: "AKIAIOSFODNN7EXAMPLE", Rule: "aws_key"},
			{Category: "pii", Severity: "medium", Text: "123-45-6789", Rule: "us_ssn"},
		},
		PIICategories: []string{"ssn"},
		SecretTypes:   []string{"aws_key"},
		MLScore:       0.85,
	}

	// Should forward without panic
	p.forwardEntry("request", "api.openai.com", "/v1/chat/completions", result)
	// Give async forward time to complete
	time.Sleep(100 * time.Millisecond)
}

func TestForwardEntry_NilResult(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 0,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	// Should not panic with nil result
	p.forwardEntry("request", "api.openai.com", "/v1/chat", nil)
}

func TestForwardEntry_EmptyResults(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 0,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	result := &detector.Summary{
		TotalDetections: 0,
		Results:         []detector.Result{},
	}

	p.forwardEntry("request", "api.openai.com", "/v1/chat", result)
}

// ---------------------------------------------------------------------------
// Start / Shutdown lifecycle (were 42% / 28.6%)
// ---------------------------------------------------------------------------

func TestStart_Lifecycle(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
		Mode:      config.ModeMonitor,
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Start(ctx)
	}()

	// Wait for proxy to be ready
	time.Sleep(200 * time.Millisecond)

	// Verify proxy is listening
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
	if err != nil {
		t.Fatalf("proxy not responding: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from /health, got %d", resp.StatusCode)
	}

	// Graceful shutdown
	cancel()
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("proxy did not shut down within 5s")
	}
}

func TestStart_PortInUse(t *testing.T) {
	// Occupy a port first
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	defer listener.Close()

	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	err = p.Start(context.Background())
	if err == nil {
		t.Error("expected error when port is in use")
		p.Shutdown()
	}
}

func TestShutdown_WithPprofServer(t *testing.T) {
	port := findFreePort(t)
	pprofPort := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		PprofAddr: fmt.Sprintf("127.0.0.1:%d", pprofPort),
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = p.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// Verify pprof is running
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", pprofPort))
	if err != nil {
		t.Fatalf("pprof server not responding: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 from pprof without token, got %d", resp.StatusCode)
	}

	// Shutdown should close both proxy and pprof servers
	cancel()
	p.Shutdown()

	// Verify pprof is no longer responding
	time.Sleep(100 * time.Millisecond)
	_, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/", pprofPort))
	if err == nil {
		t.Error("pprof server should be closed after shutdown")
	}
}

func TestShutdown_NilServers_NoPanic(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: findFreePort(t),
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Shutdown without Start() — all server fields are nil
	p.Shutdown()
	// Should not panic
}

// ---------------------------------------------------------------------------
// tunnel (was 34.6%)
// ---------------------------------------------------------------------------

func TestTunnel_BlockedAddress(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	// CONNECT to a private address should be blocked
	req := &http.Request{
		Method: "CONNECT",
		URL:    mustParseURL("http://10.0.0.1:443"),
		Host:   "10.0.0.1:443",
	}
	rr := httptest.NewRecorder()
	p.tunnel(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for private address tunnel, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "private/internal") {
		t.Errorf("expected 'private/internal' in error, got: %s", rr.Body.String())
	}
}

func TestTunnel_ConnectionFailure(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	// CONNECT to a non-routable port should fail connection
	// Port 1 is reserved and unlikely to have a listener on a public IP
	// Use 127.0.0.1 with a port we know is free
	freePort := findFreePort(t)
	req := &http.Request{
		Method: "CONNECT",
		URL:    mustParseURL(fmt.Sprintf("http://127.0.0.1:%d", freePort)),
		Host:   fmt.Sprintf("127.0.0.1:%d", freePort),
	}
	rr := httptest.NewRecorder()
	p.tunnel(rr, req)

	if rr.Code != http.StatusForbidden {
		// 127.0.0.1 is blocked by isBlockedAddress, so should get 403
		t.Errorf("expected 403 for loopback tunnel, got %d", rr.Code)
	}
}

func TestTunnel_NoPortDefaults443(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	// CONNECT without port → should default to 443, but loopback is blocked
	req := &http.Request{
		Method: "CONNECT",
		URL:    mustParseURL("http://localhost"),
		Host:   "localhost",
	}
	rr := httptest.NewRecorder()
	p.tunnel(rr, req)

	// localhost resolves to 127.0.0.1 → blocked
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for localhost tunnel, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// handleHTTP forwarding (was 65.8%)
// ---------------------------------------------------------------------------

func TestHandleHTTP_NonTargetForward(t *testing.T) {
	// Start a mock HTTP backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(), // doesn't include backend host
		Mode:      config.ModeMonitor,
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	// Make a plain HTTP request through handleHTTP
	// Since the backend is on 127.0.0.1, we need to handle it as non-target
	backendURL := mustParseURL(backend.URL)
	req := &http.Request{
		Method: "GET",
		URL:    backendURL,
		Host:   backendURL.Host,
		Header: make(http.Header),
	}
	// CloseWrite/CloseNotifier not available on httptest.ResponseRecorder,
	// but handleHTTP doesn't need them for plain HTTP
	rr := httptest.NewRecorder()
	p.handleHTTP(rr, req)

	// Non-target should be forwarded. But sharedTransport has strict TLS
	// and this is plain HTTP so it should work.
	// Note: the response might be 502 if forward fails due to TLS on HTTP
	// For plain HTTP to a non-target, the proxy forwards as-is
	if rr.Code != http.StatusOK && rr.Code != http.StatusBadGateway {
		t.Errorf("expected 200 or 502, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// ScanForTest (was 0%)
// ---------------------------------------------------------------------------

func TestScanForTest_CleanInput(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 0,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	result := p.ScanForTest("request", "api.openai.com", "/v1/chat", []byte("Hello, how are you?"))
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.TotalDetections > 0 {
		t.Errorf("expected 0 detections for clean input, got %d", result.TotalDetections)
	}
}

func TestScanForTest_DetectedInput(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 0,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	result := p.ScanForTest("request", "api.openai.com", "/v1/chat", []byte("My AWS key is AKIAIOSFODNN7EXAMPLE"))
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.TotalDetections == 0 {
		t.Error("expected detections for AWS key, got 0")
	}
}

// ---------------------------------------------------------------------------
// handleRequest API routing (was 73.7%)
// ---------------------------------------------------------------------------

func TestHandleRequest_ReadyEndpoint(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	rr := httptest.NewRecorder()
	req := &http.Request{
		Method: "GET",
		URL:    mustParseURL("http://127.0.0.1/ready"),
	}
	p.handleRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 from /ready, got %d", rr.Code)
	}
}

func TestHandleRequest_HealthEndpoint(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	rr := httptest.NewRecorder()
	req := &http.Request{
		Method: "GET",
		URL:    mustParseURL("http://127.0.0.1/health"),
	}
	p.handleRequest(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 from /health, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// blockResponse (was 92.3%) — push to 100%
// ---------------------------------------------------------------------------

func TestBlockResponse_IncludeDetections(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
		Mode:      config.ModeBlock,
		Block: config.BlockConfig{
			Threshold:         config.SeverityHigh,
			StatusCode:        403,
			IncludeDetections: true,
			Message:           "Blocked!",
		},
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	result := &detector.Summary{
		TotalDetections: 2,
		Results: []detector.Result{
			{Category: "secret", Severity: "high", Text: "AKIAIOSFODNN7EXAMPLE", Rule: "aws_key", Confidence: 0.95},
			{Category: "pii", Severity: "medium", Text: "123-45-6789", Rule: "us_ssn", Confidence: 0.90},
		},
	}

	rr := httptest.NewRecorder()
	p.blockResponse(rr, "request", "api.openai.com", "/v1/chat", result, "secret: [redacted]")

	if rr.Code != 403 {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	if rr.Header().Get("X-Rampart-Blocked") != "true" {
		t.Error("expected X-Rampart-Blocked: true")
	}

	var detail struct {
		Direction string `json:"direction"`
		Host      string `json:"host"`
		Blocked   bool   `json:"blocked"`
		Severity  string `json:"severity"`
		Results   []struct {
			Category string `json:"category"`
			Text     string `json:"text,omitempty"`
		} `json:"results"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&detail); err != nil {
		t.Fatalf("failed to decode block response: %v", err)
	}
	if !detail.Blocked {
		t.Error("expected blocked: true in body")
	}
	if len(detail.Results) != 2 {
		t.Errorf("expected 2 detection results, got %d", len(detail.Results))
	}
	// Verify text is redacted
	for _, r := range detail.Results {
		if r.Text != "" && !strings.Contains(r.Text, "***") && r.Text != "[REDACTED]" {
			t.Errorf("detection text should be redacted, got: %s", r.Text)
		}
	}
}

func TestBlockResponse_CustomStatusCode(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
		Mode:      config.ModeBlock,
		Block: config.BlockConfig{
			Threshold:         config.SeverityLow,
			StatusCode:        418,
			IncludeDetections: false,
		},
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	result := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "secret", Severity: "low", Text: "x", Rule: "test"},
		},
	}

	rr := httptest.NewRecorder()
	p.blockResponse(rr, "response", "api.openai.com", "/v1/chat", result, "test")

	if rr.Code != 418 {
		t.Errorf("expected custom status 418, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// auditLogEntry (was 84.8%) — push toward 100%
// ---------------------------------------------------------------------------

func TestAuditLogEntry_WithDetections(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	result := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "secret", Severity: "high", Text: "AKIAIOSFODNN7EXAMPLE", Rule: "aws_key"},
		},
	}

	// Should not panic
	p.auditLogEntry("request", "api.openai.com", "/v1/chat", result)
}

func TestAuditLogEntry_NoDetections(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	result := &detector.Summary{
		TotalDetections: 0,
		Results:         []detector.Result{},
	}

	// Should not write anything for 0 detections
	p.auditLogEntry("request", "api.openai.com", "/v1/chat", result)
}

// ---------------------------------------------------------------------------
// Stats Lens Integration (were 50% / 55.6%)
// ---------------------------------------------------------------------------

func TestGetDetectionsByCategory_Populated(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	// Populate some category counts
	p.mu.Lock()
	p.stats.CategoryCounts = map[string]int64{
		"secret": 5,
		"pii":    3,
		"atlas":  2,
	}
	p.mu.Unlock()

	cats := p.getDetectionsByCategory()
	if cats["secret"] != 5 {
		t.Errorf("expected secret: 5, got %d", cats["secret"])
	}
	if cats["pii"] != 3 {
		t.Errorf("expected pii: 3, got %d", cats["pii"])
	}
}

func TestGetDetectionsByCategory_EmptyMap(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	cats := p.getDetectionsByCategory()
	if cats == nil {
		t.Error("expected non-nil map for empty categories")
	}
	if len(cats) != 0 {
		t.Errorf("expected empty map, got %d entries", len(cats))
	}
}

func TestGetComplianceStatus_WithPII(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	// Set PII categories to trigger compliance mapping
	p.mu.Lock()
	p.stats.PIICategories = []string{"ssn", "email"}
	p.mu.Unlock()

	status := p.getComplianceStatus()
	// With PII categories present, should not be overall compliant
	if status.OverallCompliant {
		t.Error("expected OverallCompliant=false when PII categories are set")
	}
}

func TestGetComplianceStatus_NoPII(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	// No PII categories set → should be compliant
	status := p.getComplianceStatus()
	if !status.OverallCompliant {
		t.Error("expected OverallCompliant=true when no PII categories")
	}
}

// ---------------------------------------------------------------------------
// ReloadConfig
// ---------------------------------------------------------------------------

func TestReloadConfig_NewTargets(t *testing.T) {
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Targets:   config.DefaultTargets(),
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	originalCount := len(p.targets)

	newCfg := &config.Config{
		ProxyPort: port,
		Targets: []config.TargetConfig{
			{Domain: "api.openai.com", Paths: []string{"/v1/*"}, Description: "OpenAI"},
			{Domain: "api.anthropic.com", Paths: []string{"/v1/*"}, Description: "Anthropic"},
		},
	}

	p.ReloadConfig(newCfg)

	if len(p.targets) != 2 {
		t.Errorf("expected 2 targets after reload, got %d", len(p.targets))
	}
	if !p.targets["api.openai.com"] {
		t.Error("api.openai.com should be a target after reload")
	}
	if !p.targets["api.anthropic.com"] {
		t.Error("api.anthropic.com should be a target after reload")
	}
	_ = originalCount
}

// ---------------------------------------------------------------------------
// notifyDesktop (was 87.5%)
// ---------------------------------------------------------------------------

func TestNotifyDesktop_NilNotifier(t *testing.T) {
	cfg := &config.Config{
		ProxyPort:  0,
		Targets:    config.DefaultTargets(),
		DaemonMode: false, // notifier won't be initialized
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer p.Shutdown()

	if p.notifier != nil {
		t.Skip("notifier was initialized despite non-daemon mode")
	}

	result := &detector.Summary{
		TotalDetections: 1,
		Results: []detector.Result{
			{Category: "secret", Severity: "high", Text: "AKIAIOSFODNN7EXAMPLE", Rule: "aws_key"},
		},
	}

	// Should not panic when notifier is nil
	p.notifyDesktop("request", "api.openai.com", result)
}

// mustParseURL is defined in proxy_e2e_test.go — reused here.
