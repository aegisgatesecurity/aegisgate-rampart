// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - IOC Pull Tests
// =========================================================================

package iocpull

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// testIOCJSON builds a valid IOC response body.
func testIOCJSON(updatedAt string) string {
	if updatedAt == "" {
		updatedAt = "2026-10-14T15:30:00Z"
	}
	return fmt.Sprintf(`{
		"api_version": "v1",
		"iocs": [
			{
				"fingerprint": "sha256:abc123def456",
				"rule_id": "prompt_injection",
				"severity": "high",
				"category": "prompt-injection",
				"peer_count": 3,
				"first_seen": "2026-10-14T10:00:00Z",
				"last_seen": "2026-10-14T15:00:00Z"
			},
			{
				"fingerprint": "sha256:789abc012def",
				"rule_id": "secret_leak",
				"severity": "critical",
				"category": "secrets",
				"peer_count": 5,
				"first_seen": "2026-10-13T08:00:00Z",
				"last_seen": "2026-10-14T14:00:00Z"
			}
		],
		"updated_at": "%s"
	}`, updatedAt)
}

// newTestPuller creates a puller pointed at the given test server URL.
func newTestPuller(url string) *IOCPuller {
	return NewWithAPIKey(url, "test-key", "test-0.1.0")
}

// -----------------------------------------------------------------------
// Constructor tests
// -----------------------------------------------------------------------

func TestNew_EmptyURL(t *testing.T) {
	p := New("")
	if p.IsEnabled() {
		t.Fatal("expected disabled puller for empty URL")
	}
	if p.cache == nil {
		t.Fatal("cache should be initialized even when disabled")
	}
}

func TestNew_NonEmptyURL(t *testing.T) {
	p := New("http://localhost:9000")
	if !p.IsEnabled() {
		t.Fatal("expected enabled puller for non-empty URL")
	}
}

func TestNewWithAPIKey(t *testing.T) {
	p := NewWithAPIKey("http://localhost:9000", "secret-key", "v1.0")
	if !p.IsEnabled() {
		t.Fatal("expected enabled puller")
	}
	if p.apiKey != "secret-key" {
		t.Fatalf("expected apiKey 'secret-key', got %q", p.apiKey)
	}
	if p.version != "v1.0" {
		t.Fatalf("expected version 'v1.0', got %q", p.version)
	}
}

func TestIsEnabled(t *testing.T) {
	disabled := New("")
	if disabled.IsEnabled() {
		t.Fatal("disabled should be false")
	}
	enabled := New("http://localhost:9000")
	if !enabled.IsEnabled() {
		t.Fatal("enabled should be true")
	}
}

// -----------------------------------------------------------------------
// Pull tests
// -----------------------------------------------------------------------

func TestPull_Disabled(t *testing.T) {
	p := New("")
	_, err := p.Pull()
	if err == nil {
		t.Fatal("expected error on disabled puller")
	}
}

func TestPull_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ioc/latest" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer auth, got %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testIOCJSON(""))
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)
	result, err := p.Pull()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FromCache {
		t.Fatal("should not be from cache on first pull")
	}
	if len(result.IOCs) != 2 {
		t.Fatalf("expected 2 IOCs, got %d", len(result.IOCs))
	}
	if result.IOCs[0].Fingerprint != "sha256:abc123def456" {
		t.Errorf("unexpected fingerprint: %s", result.IOCs[0].Fingerprint)
	}
	if result.IOCs[0].RuleID != "prompt_injection" {
		t.Errorf("unexpected rule_id: %s", result.IOCs[0].RuleID)
	}
	if result.IOCs[0].PeerCount != 3 {
		t.Errorf("unexpected peer_count: %d", result.IOCs[0].PeerCount)
	}
}

func TestPull_NotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First request: return 200 with IOCs
		// Subsequent requests: return 304
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)

	// Pre-populate cache so we have something to serve on 304
	p.cache.Store([]IOCEntry{
		{Fingerprint: "sha256:cached1", RuleID: "cached_rule"},
	}, p.nowFunc())
	p.lastUpdated = "2026-10-14T15:30:00Z"

	result, err := p.Pull()
	if err != nil {
		t.Fatalf("unexpected error on 304: %v", err)
	}
	if !result.FromCache {
		t.Fatal("expected FromCache=true on 304")
	}
	if len(result.IOCs) != 1 {
		t.Fatalf("expected 1 cached IOC, got %d", len(result.IOCs))
	}
	if result.IOCs[0].Fingerprint != "sha256:cached1" {
		t.Errorf("expected cached fingerprint, got %s", result.IOCs[0].Fingerprint)
	}
}

func TestPull_AuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)
	_, err := p.Pull()
	if err == nil {
		t.Fatal("expected error on 401")
	}
}

func TestPull_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)
	_, err := p.Pull()
	if err == nil {
		t.Fatal("expected error on 500")
	}
}

// -----------------------------------------------------------------------
// Cache / lookup tests
// -----------------------------------------------------------------------

func TestGetIOC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testIOCJSON(""))
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)
	if _, err := p.Pull(); err != nil {
		t.Fatalf("pull error: %v", err)
	}

	entry, ok := p.GetIOC("sha256:abc123def456")
	if !ok {
		t.Fatal("expected to find IOC by fingerprint")
	}
	if entry.RuleID != "prompt_injection" {
		t.Errorf("unexpected rule_id: %s", entry.RuleID)
	}

	// Not found
	_, ok = p.GetIOC("sha256:nonexistent")
	if ok {
		t.Fatal("expected not found for unknown fingerprint")
	}
}

func TestCheckFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testIOCJSON(""))
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)
	if _, err := p.Pull(); err != nil {
		t.Fatalf("pull error: %v", err)
	}

	// Found
	entry := p.CheckFingerprint("sha256:789abc012def")
	if entry == nil {
		t.Fatal("expected non-nil entry for known fingerprint")
	}
	if entry.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %s", entry.Severity)
	}

	// Not found
	entry = p.CheckFingerprint("sha256:doesnotexist")
	if entry != nil {
		t.Fatal("expected nil for unknown fingerprint")
	}
}

func TestCacheSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testIOCJSON(""))
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)
	if p.CacheSize() != 0 {
		t.Fatalf("expected cache size 0 before pull, got %d", p.CacheSize())
	}
	if _, err := p.Pull(); err != nil {
		t.Fatalf("pull error: %v", err)
	}
	if p.CacheSize() != 2 {
		t.Fatalf("expected cache size 2 after pull, got %d", p.CacheSize())
	}
}

func TestGetAllIOCs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testIOCJSON(""))
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)
	if _, err := p.Pull(); err != nil {
		t.Fatalf("pull error: %v", err)
	}

	all := p.GetAllIOCs()
	if len(all) != 2 {
		t.Fatalf("expected 2 IOCs, got %d", len(all))
	}

	// Verify both fingerprints are present
	fps := map[string]bool{}
	for _, e := range all {
		fps[e.Fingerprint] = true
	}
	if !fps["sha256:abc123def456"] || !fps["sha256:789abc012def"] {
		t.Fatal("missing expected fingerprints in GetAllIOCs")
	}
}

// -----------------------------------------------------------------------
// Healthz tests
// -----------------------------------------------------------------------

func TestHealthz_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("expected /healthz, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)
	if err := p.Healthz(); err != nil {
		t.Fatalf("unexpected healthz error: %v", err)
	}
}

func TestHealthz_Disabled(t *testing.T) {
	p := New("")
	err := p.Healthz()
	if err == nil {
		t.Fatal("expected error on disabled puller healthz")
	}
}

// -----------------------------------------------------------------------
// StartPullLoop test
// -----------------------------------------------------------------------

func TestStartPullLoop(t *testing.T) {
	var pullCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&pullCount, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testIOCJSON(""))
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run loop with short interval
	p.StartPullLoop(ctx, 50*time.Millisecond)

	// Wait for at least 2 pulls (initial + 1 tick)
	time.Sleep(200 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond) // let goroutine exit

	count := atomic.LoadInt32(&pullCount)
	if count < 2 {
		t.Fatalf("expected at least 2 pulls, got %d", count)
	}
	if p.CacheSize() != 2 {
		t.Fatalf("expected cache size 2 after loop, got %d", p.CacheSize())
	}
}

// -----------------------------------------------------------------------
// Additional: If-Modified-Since header test
// -----------------------------------------------------------------------

func TestPull_IfModifiedSinceSent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ims := r.Header.Get("If-Modified-Since")
		if ims == "" {
			// First call — return 200
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, testIOCJSON("2026-10-14T16:00:00Z"))
			return
		}
		// Second call — we received If-Modified-Since, return 304
		if ims != "2026-10-14T16:00:00Z" {
			t.Errorf("unexpected If-Modified-Since: %s", ims)
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)

	// First pull — 200
	result, err := p.Pull()
	if err != nil {
		t.Fatalf("first pull error: %v", err)
	}
	if result.FromCache {
		t.Fatal("first pull should not be from cache")
	}

	// Second pull — should send If-Modified-Since, get 304
	result, err = p.Pull()
	if err != nil {
		t.Fatalf("second pull error: %v", err)
	}
	if !result.FromCache {
		t.Fatal("second pull should be from cache (304)")
	}
}

// -----------------------------------------------------------------------
// LastUpdated test
// -----------------------------------------------------------------------

func TestLastUpdated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testIOCJSON(""))
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)

	// Before pull — zero time
	if !p.LastUpdated().IsZero() {
		t.Fatal("expected zero time before pull")
	}

	if _, err := p.Pull(); err != nil {
		t.Fatalf("pull error: %v", err)
	}

	// After pull — should be non-zero
	if p.LastUpdated().IsZero() {
		t.Fatal("expected non-zero time after pull")
	}
}

// -----------------------------------------------------------------------
// Malformed JSON test
// -----------------------------------------------------------------------

func TestPull_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"bad json`)
	}))
	defer srv.Close()

	p := newTestPuller(srv.URL)
	_, err := p.Pull()
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

// -----------------------------------------------------------------------
// Valid JSON structure round-trip test
// -----------------------------------------------------------------------

func TestIOCResponse_Unmarshal(t *testing.T) {
	raw := testIOCJSON("2026-10-14T12:00:00Z")
	var resp iocResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.APIVersion != "v1" {
		t.Errorf("expected api_version v1, got %s", resp.APIVersion)
	}
	if len(resp.IOCs) != 2 {
		t.Fatalf("expected 2 IOCs, got %d", len(resp.IOCs))
	}
	if resp.UpdatedAt != "2026-10-14T12:00:00Z" {
		t.Errorf("unexpected updated_at: %s", resp.UpdatedAt)
	}
}
