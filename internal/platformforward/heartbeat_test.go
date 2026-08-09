// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Platform Forwarder Heartbeat Tests
// =========================================================================
//
// Tests for Platform connectivity checking (heartbeat/ping).
//
// Run: go test -v ./internal/platformforward/ -run TestHeartbeat -timeout 60s
//
// =========================================================================

package platformforward

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHeartbeat_Success tests successful heartbeat to Platform
func TestHeartbeat_Success(t *testing.T) {
	// Create mock Platform server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status": "healthy"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create forwarder
	f := New(server.URL)
	if !f.Enabled() {
		t.Fatal("Expected forwarder to be enabled")
	}

	// Perform heartbeat
	result := f.Heartbeat()

	if !result.Success {
		t.Errorf("Expected success, got error: %s", result.Error)
	}
	if result.Latency <= 0 {
		t.Errorf("Expected positive latency, got: %v", result.Latency)
	}
	if result.Error != "" {
		t.Errorf("Expected no error, got: %s", result.Error)
	}

	t.Logf("✓ Heartbeat successful (latency: %v)", result.Latency)
}

// TestHeartbeat_WithAPIKey tests heartbeat with API key authentication
func TestHeartbeat_WithAPIKey(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create forwarder with API key
	f := NewWithAPIKey(server.URL, "test-api-key-123")

	// Perform heartbeat
	result := f.Heartbeat()

	if !result.Success {
		t.Errorf("Expected success, got error: %s", result.Error)
	}
	if authHeader != "Bearer test-api-key-123" {
		t.Errorf("Expected Bearer token, got: %s", authHeader)
	}

	t.Logf("✓ Heartbeat with API key successful")
}

// TestHeartbeat_Disabled tests heartbeat when forwarding is disabled
func TestHeartbeat_Disabled(t *testing.T) {
	// Create forwarder with empty URL (disabled)
	f := New("")

	if f.Enabled() {
		t.Fatal("Expected forwarder to be disabled")
	}

	// Perform heartbeat
	result := f.Heartbeat()

	if result.Success {
		t.Error("Expected failure when disabled")
	}
	if result.Error != "platform forwarding disabled" {
		t.Errorf("Expected disabled error, got: %s", result.Error)
	}

	t.Logf("✓ Heartbeat correctly reports disabled state")
}

// TestHeartbeat_ServerError tests heartbeat with server error response
func TestHeartbeat_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	f := New(server.URL)
	result := f.Heartbeat()

	if result.Success {
		t.Error("Expected failure with 500 response")
	}
	if result.Error != "HTTP 500" {
		t.Errorf("Expected HTTP 500 error, got: %s", result.Error)
	}

	t.Logf("✓ Heartbeat correctly handles server errors")
}

// TestHeartbeat_ConnectionError tests heartbeat with unreachable server
func TestHeartbeat_ConnectionError(t *testing.T) {
	// Use a URL that will fail to connect
	f := New("http://localhost:9999")
	result := f.Heartbeat()

	if result.Success {
		t.Error("Expected failure with unreachable server")
	}
	if result.Error == "" {
		t.Error("Expected error message")
	}

	t.Logf("✓ Heartbeat correctly handles connection errors: %s", result.Error)
}

// TestHeartbeat_InvalidURL tests heartbeat with malformed URL
func TestHeartbeat_InvalidURL(t *testing.T) {
	// Use an invalid URL
	f := New("://invalid-url")
	result := f.Heartbeat()

	if result.Success {
		t.Error("Expected failure with invalid URL")
	}
	if result.Error == "" {
		t.Error("Expected error message")
	}

	t.Logf("✓ Heartbeat correctly handles invalid URLs: %s", result.Error)
}

// TestHeartbeat_LatencyMeasurement tests that latency is measured correctly
func TestHeartbeat_LatencyMeasurement(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	f := New(server.URL)
	result := f.Heartbeat()

	if !result.Success {
		t.Fatalf("Heartbeat failed: %s", result.Error)
	}
	if result.Latency < 100*time.Millisecond {
		t.Errorf("Expected latency >= 100ms, got: %v", result.Latency)
	}

	t.Logf("✓ Latency measurement accurate (%v)", result.Latency)
}

// TestHeartbeatResult_JSON tests HeartbeatResult JSON serialization
func TestHeartbeatResult_JSON(t *testing.T) {
	result := HeartbeatResult{
		Success:   true,
		Latency:   42 * time.Millisecond,
		Timestamp: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var decoded HeartbeatResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	if decoded.Success != result.Success {
		t.Errorf("Success mismatch")
	}
	if decoded.Latency != result.Latency {
		t.Errorf("Latency mismatch")
	}

	t.Logf("✓ HeartbeatResult JSON serialization works")
}

// TestStartHeartbeatLoop tests the periodic heartbeat loop
func TestStartHeartbeatLoop(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	f := New(server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start heartbeat loop with 100ms interval
	results := f.StartHeartbeatLoop(ctx, 100*time.Millisecond)

	// Collect results
	resultCount := 0
	for range results {
		resultCount++
		if resultCount >= 3 {
			break
		}
	}

	if resultCount < 2 {
		t.Errorf("Expected at least 2 heartbeat results, got %d", resultCount)
	}
	if requestCount < 2 {
		t.Errorf("Expected at least 2 server requests, got %d", requestCount)
	}

	t.Logf("✓ Heartbeat loop working (%d results, %d requests)", resultCount, requestCount)
}

// TestStartHeartbeatLoop_Cancellation tests that the loop stops on context cancellation
func TestStartHeartbeatLoop_Cancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	f := New(server.URL)
	ctx, cancel := context.WithCancel(context.Background())

	// Start heartbeat loop
	results := f.StartHeartbeatLoop(ctx, 50*time.Millisecond)

	// Get one result
	<-results

	// Cancel context
	cancel()

	// Wait for channel to close
	select {
	case _, ok := <-results:
		if ok {
			t.Error("Expected channel to be closed after cancellation")
		}
	case <-time.After(1 * time.Second):
		t.Error("Channel didn't close after cancellation")
	}

	t.Logf("✓ Heartbeat loop correctly stops on cancellation")
}

// TestStartHeartbeatLoop_ChannelFull tests that the loop handles full channel gracefully
func TestStartHeartbeatLoop_ChannelFull(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	f := New(server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// Start heartbeat loop with very short interval
	results := f.StartHeartbeatLoop(ctx, 10*time.Millisecond)

	// Don't read from channel - let it fill up
	time.Sleep(250 * time.Millisecond)

	// Should not panic or block
	t.Logf("✓ Heartbeat loop handles full channel gracefully")

	// Read remaining results
	count := 0
	for range results {
		count++
	}
	t.Logf("Read %d results after stopping", count)
}
