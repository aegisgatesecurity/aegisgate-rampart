// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Anonymized Metrics Collection
// =========================================================================
//
// Privacy-preserving telemetry for product improvement. Opt-in only.
// No prompt text, no PII values, no URLs, no user identifiers.
//
// Design principles (from Lens):
//   1. No data transmitted by default (opt-in only)
//   2. Domain hashed (SHA-256, 16 hex chars, can't reverse)
//   3. Timestamp rounded to hour (can't correlate events)
//   4. Only false positives sent (user-confirmed)
//   5. Metadata sanitized (no IPs, no sessions, no fingerprints)
//
// Collection endpoint: https://rampart.aegisgatesecurity.io/metrics
// =========================================================================

package metrics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/version"
)

const (
	// DefaultMetricsEndpoint is the collection endpoint
	DefaultMetricsEndpoint = "https://rampart.aegisgatesecurity.io/metrics"

	// BatchSize is the number of metrics to batch before sending
	BatchSize = 10

	// BatchTimeout is the maximum time to wait before sending a partial batch
	BatchTimeout = 5 * time.Minute

	// HTTPTimeout for metric uploads
	HTTPTimeout = 10 * time.Second

	// Domain hash length (16 hex chars = 64 bits)
	DomainHashLength = 16
)

// AnonymizedMetric represents a single privacy-preserving metric
type AnonymizedMetric struct {
	// Rampart version (e.g., "0.5.0")
	Version string `json:"rampart_version"`

	// Platform (e.g., "linux-amd64")
	Platform string `json:"platform"`

	// Hashed domain (SHA-256 truncated to 16 hex chars)
	DomainHash string `json:"domain_hash"`

	// Detection category (e.g., "pii_ssn", "secret_aws_key")
	Category string `json:"category"`

	// Severity (low, medium, high, critical)
	Severity string `json:"severity"`

	// Whether the request was blocked
	Blocked bool `json:"blocked"`

	// Timestamp rounded to hour (prevents correlation)
	Hour time.Time `json:"hour"`

	// False positive flag (only sent if user confirms FP)
	FalsePositive bool `json:"false_positive,omitempty"`

	// User action taken (only for false positives)
	UserAction string `json:"user_action,omitempty"`
}

// Collector collects and sends anonymized metrics
type Collector struct {
	mu          sync.Mutex
	enabled     bool
	endpoint    string
	client      *http.Client
	queue       []AnonymizedMetric
	batchTimer  *time.Timer
	domainCache map[string]string
	ctx         context.Context
	cancel      context.CancelFunc

	// For testing
	sendFunc func([]AnonymizedMetric) error
}

// NewCollector creates a new anonymized metrics collector
func NewCollector(enabled bool, endpoint string) *Collector {
	if endpoint == "" {
		endpoint = DefaultMetricsEndpoint
	}

	ctx, cancel := context.WithCancel(context.Background())

	c := &Collector{
		enabled:     enabled,
		endpoint:    endpoint,
		domainCache: make(map[string]string),
		ctx:         ctx,
		cancel:      cancel,
		client: &http.Client{
			Timeout: HTTPTimeout,
		},
		queue: make([]AnonymizedMetric, 0, BatchSize),
	}

	// Start batch timer
	c.batchTimer = time.AfterFunc(BatchTimeout, c.sendBatch)

	return c
}

// RecordDetection records a detection event (anonymized)
func (c *Collector) RecordDetection(host, category, severity string, blocked bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		return
	}

	// Hash domain
	domainHash := c.hashDomain(host)

	// Round timestamp to hour
	hour := time.Now().Truncate(time.Hour)

	metric := AnonymizedMetric{
		Version:    version.Version,
		Platform:   getPlatform(),
		DomainHash: domainHash,
		Category:   category,
		Severity:   severity,
		Blocked:    blocked,
		Hour:       hour,
	}

	c.queue = append(c.queue, metric)

	// Send if batch is full
	if len(c.queue) >= BatchSize {
		c.sendBatchLocked()
	}
}

// RecordFalsePositive records a user-confirmed false positive
func (c *Collector) RecordFalsePositive(host, category, severity string, action string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		return
	}

	domainHash := c.hashDomain(host)
	hour := time.Now().Truncate(time.Hour)

	metric := AnonymizedMetric{
		Version:       version.Version,
		Platform:      getPlatform(),
		DomainHash:    domainHash,
		Category:      category,
		Severity:      severity,
		Blocked:       false,
		Hour:          hour,
		FalsePositive: true,
		UserAction:    action,
	}

	c.queue = append(c.queue, metric)

	if len(c.queue) >= BatchSize {
		c.sendBatchLocked()
	}
}

// hashDomain computes SHA-256 hash of domain, truncated to 16 hex chars
func (c *Collector) hashDomain(domain string) string {
	// Check cache first
	if hash, ok := c.domainCache[domain]; ok {
		return hash
	}

	// Normalize domain (lowercase, strip port)
	normalized := normalizeDomain(domain)

	// Compute SHA-256
	h := sha256.Sum256([]byte(normalized))
	hash := hex.EncodeToString(h[:])[:DomainHashLength]

	// Cache for future use
	c.domainCache[domain] = hash

	return hash
}

// normalizeDomain normalizes a domain for hashing
func normalizeDomain(domain string) string {
	// Lowercase
	domain = strings.ToLower(domain)

	// Strip port if present
	if idx := strings.IndexByte(domain, ':'); idx != -1 {
		domain = domain[:idx]
	}

	// Strip leading www.
	domain = strings.TrimPrefix(domain, "www.")

	return domain
}

// sendBatch sends the current batch of metrics
func (c *Collector) sendBatch() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendBatchLocked()
}

// sendBatchLocked sends batch (caller must hold lock)
func (c *Collector) sendBatchLocked() {
	if len(c.queue) == 0 {
		return
	}

	batch := make([]AnonymizedMetric, len(c.queue))
	copy(batch, c.queue)
	c.queue = c.queue[:0]

	// Reset timer
	c.batchTimer.Reset(BatchTimeout)

	// Send (or use test function)
	if c.sendFunc != nil {
		_ = c.sendFunc(batch)
		return
	}

	// Send to endpoint
	go c.sendToEndpoint(batch)
}

// sendToEndpoint sends metrics to the collection endpoint
func (c *Collector) sendToEndpoint(batch []AnonymizedMetric) {
	data, err := json.Marshal(batch)
	if err != nil {
		// Marshal failed, drop metrics (don't block)
		return
	}

	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.endpoint, bytes.NewReader(data))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AegisGate-Rampart/"+version.Version)

	resp, err := c.client.Do(req)
	if err != nil {
		// Network error, drop metrics (don't retry to preserve privacy)
		return
	}
	defer resp.Body.Close()

	// Don't check response status - we want to preserve privacy
	// even if the server rejects the metrics
}

// Flush sends any pending metrics and stops the collector
func (c *Collector) Flush() {
	c.sendBatch()
	c.cancel()
}

// SetEnabled enables or disables metrics collection
func (c *Collector) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

// IsEnabled returns whether metrics collection is enabled
func (c *Collector) IsEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled
}

// GetQueueLength returns the current queue length (for testing)
func (c *Collector) GetQueueLength() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.queue)
}

// getPlatform returns the current platform string
func getPlatform() string {
	return fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
}

// Close closes the collector and sends any pending metrics
func (c *Collector) Close() error {
	c.Flush()
	return nil
}

// HashDomainForTest exposes domain hashing for testing (test-only)
func (c *Collector) HashDomainForTest(domain string) string {
	return c.hashDomain(domain)
}
