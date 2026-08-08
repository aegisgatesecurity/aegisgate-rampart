// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — LSP HTTP Client
// =========================================================================
// HTTP client that calls the local Rampart /detect endpoint.
// Mirrors the VS Code / IntelliJ extension client pattern.
// =========================================================================

package lsp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DetectRequest is the JSON body sent to the Rampart /detect endpoint.
type DetectRequest struct {
	Text string `json:"text"`
}

// DetectResult represents a single detection from Rampart.
type DetectResult struct {
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Text        string  `json:"text,omitempty"`
	Rule        string  `json:"rule"`
	IsThreat    bool    `json:"is_threat"`
	Blocked     bool    `json:"blocked"`
	BlockReason string  `json:"block_reason,omitempty"`
	MLScore     float64 `json:"ml_score,omitempty"`
}

// DetectSummary is the full response from the /detect endpoint.
type DetectSummary struct {
	TotalDetections int             `json:"total_detections"`
	Blocked         bool            `json:"blocked"`
	BlockReason     string          `json:"block_reason,omitempty"`
	Results         []DetectResult  `json:"results"`
	PIICategories   []string        `json:"pii_categories,omitempty"`
	SecretTypes     []string        `json:"secret_types,omitempty"`
	Compliance      map[string]bool `json:"compliance,omitempty"`
	MLScore         float64         `json:"ml_score,omitempty"`
	LatencyMs       int64           `json:"latency_ms"`
}

// ProxyStats represents the response from the Rampart /stats endpoint.
type ProxyStats struct {
	TotalRequests   int64  `json:"total_requests"`
	Intercepted     int64  `json:"intercepted"`
	PassedThrough   int64  `json:"passed_through"`
	Detections      int64  `json:"detections"`
	BlockedRequests int64  `json:"blocked_requests"`
	MLDetections    int64  `json:"ml_detections"`
	StartTime       string `json:"start_time"`
	Mode            string `json:"mode"`
}

// RampartClient calls the Rampart local HTTP /detect endpoint.
type RampartClient struct {
	url        string
	httpClient *http.Client
}

// NewRampartClient creates a client targeting the Rampart server at url.
func NewRampartClient(url string) *RampartClient {
	return &RampartClient{
		url: url,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetStats calls the Rampart /stats endpoint and returns proxy statistics.
func (c *RampartClient) GetStats(ctx context.Context) (*ProxyStats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/stats", nil)
	if err != nil {
		return nil, fmt.Errorf("create stats request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stats request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("stats returned status %d: %s", resp.StatusCode, string(body))
	}

	var stats ProxyStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("decode stats response: %w", err)
	}

	return &stats, nil
}

// Detect sends text to the Rampart /detect endpoint and returns the summary.
func (c *RampartClient) Detect(ctx context.Context, text string) (*DetectSummary, error) {
	reqBody, err := json.Marshal(DetectRequest{Text: text})
	if err != nil {
		return nil, fmt.Errorf("marshal detect request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/detect", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create detect request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("detect request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("detect returned status %d: %s", resp.StatusCode, string(body))
	}

	var summary DetectSummary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return nil, fmt.Errorf("decode detect response: %w", err)
	}

	return &summary, nil
}
