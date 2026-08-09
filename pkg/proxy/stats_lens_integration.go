// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Stats API Lens Integration
// =========================================================================
//
// Enhances /stats endpoint for Lens browser extension integration.
// Provides real-time detection statistics and compliance status.
//
// Lens Integration:
//   - CORS enabled for browser extension access
//   - Extended stats with detection breakdown
//   - Compliance framework summary
//   - Real-time monitoring support
//
// =========================================================================

package proxy

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/response"
)

// LensStats extends ProxyStats with Lens-specific fields
type LensStats struct {
	ProxyStats

	// Lens-specific fields
	UptimeSeconds        int64                     `json:"uptime_seconds"`
	DetectionsByCategory map[string]int64          `json:"detections_by_category"`
	ComplianceStatus     response.ComplianceStatus `json:"compliance_status"`
	LastDetectionTime    time.Time                 `json:"last_detection_time,omitempty"`
	AvgLatencyMs         float64                   `json:"avg_latency_ms,omitempty"`
}

// HandleStatsAPILens serves the enhanced /stats endpoint for Lens integration
// GET /stats → extended proxy statistics with Lens-specific fields
func (p *Proxy) HandleStatsAPILens(w http.ResponseWriter, r *http.Request) {
	// Enable CORS for Lens browser extension
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight requests
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit: protect against polling abuse
	if !p.rateLimiter.Allow() {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Get base stats
	baseStats := p.GetStats()

	// Build extended stats
	lensStats := LensStats{
		ProxyStats:           baseStats,
		UptimeSeconds:        int64(time.Since(baseStats.StartTime).Seconds()),
		DetectionsByCategory: p.getDetectionsByCategory(),
		ComplianceStatus:     p.getComplianceStatus(),
		LastDetectionTime:    p.getLastDetectionTime(),
		AvgLatencyMs:         p.getAverageLatency(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(lensStats); err != nil {
		http.Error(w, "Failed to encode stats", http.StatusInternalServerError)
		return
	}
}

// getDetectionsByCategory returns detection counts by category
func (p *Proxy) getDetectionsByCategory() map[string]int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.stats.CategoryCounts == nil {
		return make(map[string]int64)
	}
	result := make(map[string]int64, len(p.stats.CategoryCounts))
	for k, v := range p.stats.CategoryCounts {
		result[k] = v
	}
	return result
}

// getComplianceStatus returns compliance framework violation counts
func (p *Proxy) getComplianceStatus() response.ComplianceStatus {
	p.mu.RLock()
	piiCats := p.stats.PIICategories
	p.mu.RUnlock()

	if len(piiCats) == 0 {
		return response.ComplianceStatus{OverallCompliant: true}
	}
	// Convert category strings to PIIMatch for compliance mapping
	matches := make([]response.PIIMatch, 0, len(piiCats))
	for _, cat := range piiCats {
		matches = append(matches, response.PIIMatch{
			Category: response.PIICategory(cat),
		})
	}
	return response.GetComplianceStatus(matches)
}

// getLastDetectionTime returns the timestamp of the last detection
func (p *Proxy) getLastDetectionTime() time.Time {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats.LastDetectionTime
}

// getAverageLatency returns average detection latency in milliseconds
func (p *Proxy) getAverageLatency() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Placeholder - to be implemented with latency tracking
	return 0.0
}
