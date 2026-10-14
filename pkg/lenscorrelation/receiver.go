// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — Lens Signal Correlation
// =========================================================================
//
// Receives detection signals from the Lens browser extension and
// correlates them with Rampart's own proxy-layer detections.
//
// =========================================================================

package lenscorrelation

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// LensSignal is a detection signal sent from the Lens browser extension.
// Contains only metadata — no prompt text, no PII values, no page content.
type LensSignal struct {
	// HashedDomain is the SHA-256 hash (16 hex chars) of the domain
	// where the detection occurred. Matches Rampart's domain hash format.
	HashedDomain string `json:"hashed_domain"`

	// Category is the detection category (e.g., "prompt_injection", "pii")
	Category string `json:"category"`

	// Severity is the detection severity: "low", "medium", "high", "critical"
	Severity string `json:"severity"`

	// RuleID is the specific rule that triggered (e.g., "owasp_llm01_prompt_injection")
	RuleID string `json:"rule_id"`

	// Timestamp is when Lens detected the signal (RFC3339)
	Timestamp string `json:"timestamp"`

	// Direction is "page" (detected on page content) or "request" (detected in outgoing request)
	Direction string `json:"direction"`

	// Action is what Lens did: "warned", "blocked", "logged"
	Action string `json:"action"`
}

// RampartDetection is a detection from Rampart's proxy layer.
// Used for correlation with Lens signals.
type RampartDetection struct {
	HashedDomain string
	Category     string
	Severity     string
	RuleID       string
	Timestamp    time.Time
	Direction    string // "request" or "response"
}

// CorrelationResult is the outcome of correlating a Lens signal with
// Rampart detections.
type CorrelationResult struct {
	// LensSignal is the original Lens signal
	LensSignal LensSignal

	// MatchingDetections are Rampart detections on the same domain
	// within the correlation window.
	MatchingDetections []RampartDetection

	// Escalated is true if the correlation warrants severity escalation
	Escalated bool

	// OriginalSeverity is the Lens signal's original severity
	OriginalSeverity string

	// EscalatedSeverity is the severity after correlation (may be same)
	EscalatedSeverity string

	// RecommendBlock is true if the combined signal warrants blocking
	RecommendBlock bool

	// Reason explains the correlation decision
	Reason string
}

// SignalReceiver accepts Lens signals via HTTP and correlates them
// with Rampart detections.
type SignalReceiver struct {
	mu     sync.Mutex
	logger *slog.Logger

	// Sliding window of recent Lens signals (for correlation)
	lensSignals []LensSignal

	// Sliding window of recent Rampart detections (for correlation)
	rampartDetections []RampartDetection

	// Configuration
	windowDuration time.Duration // How long to keep signals for correlation
	maxSignals     int           // Max signals to keep in memory

	// Statistics
	stats ReceiverStats
}

// ReceiverStats tracks signal receiver statistics.
type ReceiverStats struct {
	TotalSignals      int64
	CorrelatedSignals int64
	EscalatedSignals  int64
	BlockedSignals    int64
}

// ---------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------

// NewSignalReceiver creates a new SignalReceiver with default settings.
func NewSignalReceiver() *SignalReceiver {
	return &SignalReceiver{
		logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
		windowDuration: 5 * time.Minute,
		maxSignals:     500,
	}
}

// SetLogger sets a custom logger.
func (r *SignalReceiver) SetLogger(l *slog.Logger) {
	r.logger = l
}

// SetWindowDuration sets how long to keep signals for correlation.
func (r *SignalReceiver) SetWindowDuration(d time.Duration) {
	r.windowDuration = d
}

// ---------------------------------------------------------------------
// Signal Reception
// ---------------------------------------------------------------------

// HandleSignal is the HTTP handler for POST /api/v1/lens-signals.
// It accepts a LensSignal JSON body, stores it, and returns the
// correlation result.
func (r *SignalReceiver) HandleSignal(w http.ResponseWriter, req *http.Request) {
	// CORS headers for browser extension access
	setCORSHeaders(w)

	// Handle preflight
	if req.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Limit body size
	req.Body = http.MaxBytesReader(w, req.Body, 1<<16) // 64KB max
	body, err := io.ReadAll(req.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "failed to read request body",
		})
		return
	}
	defer req.Body.Close()

	var signal LensSignal
	if err := json.Unmarshal(body, &signal); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":   "invalid JSON",
			"details": err.Error(),
		})
		return
	}

	// Validate signal
	if err := validateSignal(signal); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	// Store and correlate
	result := r.ProcessSignal(signal)

	// Return correlation result
	writeJSON(w, http.StatusOK, result)
}

// ProcessSignal stores a Lens signal and correlates it with recent
// Rampart detections.
func (r *SignalReceiver) ProcessSignal(signal LensSignal) CorrelationResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Store signal
	r.lensSignals = append(r.lensSignals, signal)
	r.pruneOldSignals()
	r.stats.TotalSignals++

	// Correlate with Rampart detections
	result := r.correlate(signal)

	if result.Escalated {
		r.stats.EscalatedSignals++
	}
	if result.RecommendBlock {
		r.stats.BlockedSignals++
	}
	if len(result.MatchingDetections) > 0 {
		r.stats.CorrelatedSignals++
	}

	return result
}

// RecordRampartDetection adds a Rampart proxy detection to the
// correlation window. Call this from Rampart's detection pipeline.
func (r *SignalReceiver) RecordRampartDetection(d RampartDetection) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.rampartDetections = append(r.rampartDetections, d)
	r.pruneOldDetections()
}

// ---------------------------------------------------------------------
// Correlation Logic
// ---------------------------------------------------------------------

// correlate checks if a Lens signal matches any recent Rampart detections.
func (r *SignalReceiver) correlate(signal LensSignal) CorrelationResult {
	result := CorrelationResult{
		LensSignal:        signal,
		OriginalSeverity:  signal.Severity,
		EscalatedSeverity: signal.Severity,
	}

	// Find matching Rampart detections (same domain, within window)
	now := time.Now()
	windowStart := now.Add(-r.windowDuration)

	for _, d := range r.rampartDetections {
		if d.Timestamp.Before(windowStart) {
			continue
		}
		if d.HashedDomain != signal.HashedDomain {
			continue
		}

		result.MatchingDetections = append(result.MatchingDetections, d)

		// Escalation logic: if both Lens and Rampart detected on same domain,
		// escalate by one severity level
		if shouldEscalate(signal.Severity, d.Severity) {
			result.Escalated = true
			result.EscalatedSeverity = escalateSeverity(signal.Severity)
			result.Reason = "cross-layer correlation: both Lens and Rampart detected on same domain"
		}

		// Block recommendation: if either layer detected critical, or both
		// detected high+
		if signal.Severity == "critical" || d.Severity == "critical" {
			result.RecommendBlock = true
			result.Reason = "critical severity detected in cross-layer correlation"
		} else if signal.Severity == "high" && d.Severity == "high" {
			result.RecommendBlock = true
			result.Reason = "dual high-severity detections across layers"
		}
	}

	if len(result.MatchingDetections) == 0 {
		result.Reason = "no matching Rampart detections in correlation window"
	}

	return result
}

// shouldEscalate determines if the combined signal warrants escalation.
func shouldEscalate(lensSev, rampartSev string) bool {
	// If either layer detected critical, always escalate
	if lensSev == "critical" || rampartSev == "critical" {
		return true
	}

	// Escalate if both layers detected high+
	lensHigh := lensSev == "high" || lensSev == "critical"
	rampartHigh := rampartSev == "high" || rampartSev == "critical"

	if lensHigh && rampartHigh {
		return true
	}
	if lensSev == "medium" && rampartSev == "medium" {
		return true
	}
	return false
}

// escalateSeverity bumps a severity level by one step.
func escalateSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "low":
		return "medium"
	case "medium":
		return "high"
	case "high":
		return "critical"
	default:
		return sev
	}
}

// ---------------------------------------------------------------------
// Pruning
// ---------------------------------------------------------------------

func (r *SignalReceiver) pruneOldSignals() {
	if len(r.lensSignals) <= r.maxSignals {
		return
	}
	// Keep most recent
	r.lensSignals = r.lensSignals[len(r.lensSignals)-r.maxSignals:]
}

func (r *SignalReceiver) pruneOldDetections() {
	if len(r.rampartDetections) <= r.maxSignals {
		return
	}
	r.rampartDetections = r.rampartDetections[len(r.rampartDetections)-r.maxSignals:]
}

// PruneExpired removes entries older than the window duration.
// Call this periodically to clean up stale entries.
func (r *SignalReceiver) PruneExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-r.windowDuration)

	// Prune Rampart detections
	var kept []RampartDetection
	for _, d := range r.rampartDetections {
		if d.Timestamp.After(windowStart) {
			kept = append(kept, d)
		}
	}
	r.rampartDetections = kept

	// Lens signals don't have parsed timestamps (they're strings from JS),
	// so we just keep the most recent maxSignals
	r.pruneOldSignals()
}

// ---------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------

// GetStats returns current receiver statistics.
func (r *SignalReceiver) GetStats() ReceiverStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

// GetSignalCount returns the number of signals in the correlation window.
func (r *SignalReceiver) GetSignalCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.lensSignals)
}

// GetDetectionCount returns the number of Rampart detections in the window.
func (r *SignalReceiver) GetDetectionCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rampartDetections)
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

func validateSignal(s LensSignal) error {
	if s.HashedDomain == "" {
		return fmt.Errorf("hashed_domain is required")
	}
	if s.Category == "" {
		return fmt.Errorf("category is required")
	}
	if s.Severity == "" {
		return fmt.Errorf("severity is required")
	}
	switch strings.ToLower(s.Severity) {
	case "low", "medium", "high", "critical":
		// valid
	default:
		return fmt.Errorf("invalid severity: %s", s.Severity)
	}
	return nil
}

// ---------------------------------------------------------------------
// HTTP Helpers
// ---------------------------------------------------------------------

// HandleHealthz is a simple health check endpoint for Lens to detect
// if Rampart is running.
func (r *SignalReceiver) HandleHealthz(w http.ResponseWriter, req *http.Request) {
	setCORSHeaders(w)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":          "ok",
		"signal_count":    r.GetSignalCount(),
		"detection_count": r.GetDetectionCount(),
	})
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
