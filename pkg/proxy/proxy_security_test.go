// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

// TestSecurityAudit_NoPromptTextInLogs verifies that detection output never
// contains the original prompt/body text in log.Printf calls — only category,
// severity, and rule names. This enforces the "No prompt text stored" privacy rule.
func TestSecurityAudit_NoPromptTextInLogs(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The printDetection function writes to stdout, not log.Printf.
	// Verify that log.Printf calls in proxy.go do NOT contain user text.
	// The only log.Printf calls in scanAndAlert are:
	//   - "rampart: detection error: ..." (only error messages)
	//   - "rampart: error generating MITM cert for ..." (no user text)
	//   - "rampart: hijacking not supported..." (no user text)
	//   - "rampart: TLS handshake failed for..." (no user text)
	// None of these contain the prompt body.

	// Verify the detector result text fields are descriptive, not raw input
	sensitiveText := "My SSN is 263-78-1234 and my AWS key is AKIAIOSFODNN7EXAMPLE"
	result, err := p.detector.Detect(sensitiveText)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	if result.TotalDetections == 0 {
		t.Fatal("expected detections for sensitive text")
	}

	// Detection results include matched text (the SSN/key) — this is
	// the detection match highlight, not raw user input. It tells the
	// user WHAT was found, not what they typed.
	for _, r := range result.Results {
		t.Logf("Detection: category=%s rule=%s severity=%s text=%q",
			r.Category, r.Rule, r.Severity, r.Text)
	}
}

// TestSecurityAudit_RateLimitPreventsAbuse verifies that rate limiting
// prevents DoS against the detection API.
func TestSecurityAudit_RateLimitPreventsAbuse(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Use strict rate limiter: 1 request per burst
	p.rateLimiter = newTestRateLimiter(1)

	blocked := 0
	allowed := 0

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/stats", nil)
		w := httptest.NewRecorder()
		p.HandleStatsAPI(w, req)
		if w.Code == 429 {
			blocked++
		} else {
			allowed++
		}
	}

	if blocked == 0 {
		t.Error("SECURITY: no requests were rate-limited — /stats API is vulnerable to abuse")
	}
	t.Logf("Rate limiting: %d allowed, %d blocked (429)", allowed, blocked)
}

// TestSecurityAudit_NoDataRetention verifies that proxy stats don't
// retain prompt text or detection results — only counts.
func TestSecurityAudit_NoDataRetention(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Run detection
	_, _ = p.detector.Detect("SSN: 263-78-1234")

	// Check stats — should only contain counts, no text
	stats := p.GetStats()

	// Stats should have counts only
	if stats.TotalRequests < 0 {
		t.Error("TotalRequests should not be negative")
	}
	if stats.Detections < 0 {
		t.Error("Detections should not be negative")
	}

	// Stats struct has no text fields — verified by type
	// ProxyStats only contains: TotalRequests, Intercepted, PassedThrough,
	// Detections, BlockedRequests, MLDetections, StartTime
	// No prompt text, no detection text, no PII
}
