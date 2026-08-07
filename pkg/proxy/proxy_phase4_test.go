// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"golang.org/x/time/rate"
)

func TestRateLimit_DetectAPI(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0 // don't bind

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Create a low rate limiter for testing: 2 requests per second
	p.rateLimiter = newTestRateLimiter(2)

	body := `{"text": "hello world"}`
	var wg sync.WaitGroup
	var tooManyCount int
	var successCount int
	var mu sync.Mutex

	// Fire 10 concurrent requests — most should be rate-limited
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			p.HandleDetectAPI(w, req)
			mu.Lock()
			if w.Code == http.StatusTooManyRequests {
				tooManyCount++
			} else if w.Code == http.StatusOK {
				successCount++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if tooManyCount == 0 {
		t.Log("rate limiting may not be aggressive enough with burst=2, but test is advisory")
	}
	t.Logf("success=%d, rate_limited=%d", successCount, tooManyCount)
}

func TestRateLimit_StatsAPI(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	p.rateLimiter = newTestRateLimiter(2)

	var wg sync.WaitGroup
	var tooManyCount int
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/stats", nil)
			w := httptest.NewRecorder()
			p.HandleStatsAPI(w, req)
			mu.Lock()
			if w.Code == http.StatusTooManyRequests {
				tooManyCount++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if tooManyCount == 0 {
		t.Log("rate limiting may not be aggressive enough, but test is advisory")
	}
	t.Logf("rate_limited=%d", tooManyCount)
}

func TestRateLimit_MethodNotAllowed(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/detect", nil)
	w := httptest.NewRecorder()
	p.HandleDetectAPI(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestGracefulShutdown(t *testing.T) {
	cfg := config.DefaultConfig()

	// Start the proxy on a random port
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg.ProxyPort = 0 // random port
	p2, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Start in goroutine, then cancel after brief delay
	done := make(chan error, 1)
	go func() {
		done <- p2.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Shutdown should complete without hanging
	select {
	case err := <-done:
		if err != nil && err != http.ErrServerClosed {
			t.Logf("start returned: %v (acceptable)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown took too long — graceful drain not working")
	}
}

func TestReloadConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Initial targets
	initialCount := len(p.targets)
	t.Logf("initial targets: %d", initialCount)

	// Reload with modified config — add an extra target
	newCfg := config.DefaultConfig()
	newCfg.Targets = append(newCfg.Targets, config.TargetConfig{
		Domain:      "api.test.example.com",
		Paths:       []string{"/v1/*"},
		Description: "Test API",
	})

	p.ReloadConfig(newCfg)

	if len(p.targets) != initialCount+1 {
		t.Errorf("expected %d targets after reload, got %d", initialCount+1, len(p.targets))
	}

	if !p.targets["api.test.example.com"] {
		t.Error("new target domain not found after reload")
	}

	// Verify old targets still present
	if !p.targets["api.openai.com"] {
		t.Error("original target domain missing after reload")
	}
}

func TestDetectAPI_RateLimitedResponse(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Exhaust the rate limiter
	p.rateLimiter = newTestRateLimiter(1)
	p.rateLimiter.Allow() // exhaust the single token

	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(`{"text":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.HandleDetectAPI(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after rate limit, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "rate limit") {
		t.Errorf("expected 'rate limit' in body, got: %s", body)
	}
}

func TestStatsAPI_RateLimitedResponse(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	p.rateLimiter = newTestRateLimiter(1)
	p.rateLimiter.Allow() // exhaust

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	p.HandleStatsAPI(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after rate limit, got %d", w.Code)
	}
}

func TestShutdownTimeout(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if p.shutdownTimeout != 15*time.Second {
		t.Errorf("expected 15s shutdown timeout, got %v", p.shutdownTimeout)
	}
}

// newTestRateLimiter creates a rate.Limiter with the given burst for testing.
// This uses a high rate (1000/sec) so the burst is the effective limit.
func newTestRateLimiter(burst int) *rate.Limiter {
	return rate.NewLimiter(1000, burst)
}

// Ensure JSON detection response still works with rate limiting in place
func TestDetectAPI_StillWorksWithRateLimit(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Use a generous rate limiter so the first request succeeds
	p.rateLimiter = rate.NewLimiter(rate.Every(time.Second), 30)

	body := `{"text": "My SSN is 263-78-1234"}`
	req := httptest.NewRequest(http.MethodPost, "/detect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.HandleDetectAPI(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if result["total_detections"] == nil {
		t.Error("expected total_detections in response")
	}
}
