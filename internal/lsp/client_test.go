// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — LSP Client Tests
// =========================================================================

package lsp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewRampartClient(t *testing.T) {
	client := NewRampartClient("http://localhost:9090")
	if client.url != "http://localhost:9090" {
		t.Errorf("expected url http://localhost:9090, got %s", client.url)
	}
	if client.httpClient.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %s", client.httpClient.Timeout)
	}
}

func TestDetectSuccess(t *testing.T) {
	summary := DetectSummary{
		TotalDetections: 2,
		Blocked:         false,
		Results: []DetectResult{
			{
				Category:   "secrets",
				Severity:   "high",
				Confidence: 0.95,
				Text:       "AWS key detected",
				Rule:       "secret_aws_key",
				IsThreat:   true,
			},
			{
				Category:   "pii",
				Severity:   "medium",
				Confidence: 0.80,
				Text:       "SSN detected",
				Rule:       "pii_ssn",
				IsThreat:   true,
			},
		},
		LatencyMs: 5,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/detect" {
			t.Errorf("expected /detect, got %s", r.URL.Path)
		}

		var req DetectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if req.Text != "hello world" {
			t.Errorf("expected text 'hello world', got %q", req.Text)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	result, err := client.Detect(context.Background(), "hello world")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalDetections != 2 {
		t.Errorf("expected 2 detections, got %d", result.TotalDetections)
	}
	if len(result.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(result.Results))
	}
	if result.Results[0].Category != "secrets" {
		t.Errorf("expected category 'secrets', got %q", result.Results[0].Category)
	}
	if result.Results[1].Rule != "pii_ssn" {
		t.Errorf("expected rule 'pii_ssn', got %q", result.Results[1].Rule)
	}
}

func TestDetectError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	_, err := client.Detect(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDetectRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	_, err := client.Detect(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for 429, got nil")
	}
}

func TestDetectContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := NewRampartClient("http://localhost:99999")
	_, err := client.Detect(ctx, "test")
	if err == nil {
		t.Fatal("expected error for canceled context, got nil")
	}
}

func TestDetectEmptyText(t *testing.T) {
	// Even empty text should make it to the server (the server returns empty results)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DetectSummary{})
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	result, err := client.Detect(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalDetections != 0 {
		t.Errorf("expected 0 detections for empty text, got %d", result.TotalDetections)
	}
}

func TestDetectInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	_, err := client.Detect(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}
