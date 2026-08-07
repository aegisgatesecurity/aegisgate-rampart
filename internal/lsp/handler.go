// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — LSP Handler
// =========================================================================
// Receives text document changes, calls the Rampart /detect endpoint
// via RampartClient, and publishes LSP diagnostics back to the editor.
// =========================================================================

package lsp

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// categoryIcons maps Rampart categories to editor-friendly icons.
var categoryIcons = map[string]string{
	"pii":               "🔐",
	"pii-us-core":       "🔐",
	"pii-us-extended":   "🔐",
	"pii-financial":     "💳",
	"pii-international": "🔐",
	"credit_card":       "💳",
	"xss":               "⚔️",
	"secrets":           "🔑",
	"secret":            "🔑",
	"prompt_injection":  "🧠",
	"compliance":        "📋",
	"ml_threat":         "🧠",
}

// severityOrder maps Rampart severity strings to LSP diagnostic severity.
// critical/high → Error, medium → Warning, low/info → Hint.
var severityOrder = map[string]DiagnosticSeverity{
	"critical": SeverityError,
	"high":     SeverityError,
	"medium":   SeverityWarning,
	"low":      SeverityHint,
	"info":     SeverityHint,
}

// SeverityThreshold represents the minimum severity to report.
type SeverityThreshold string

const (
	ThresholdCritical SeverityThreshold = "critical"
	ThresholdHigh     SeverityThreshold = "high"
	ThresholdMedium   SeverityThreshold = "medium"
	ThresholdLow      SeverityThreshold = "low"
)

// thresholdLevels assigns numeric levels for threshold comparison.
var thresholdLevels = map[SeverityThreshold]int{
	ThresholdCritical: 4,
	ThresholdHigh:     3,
	ThresholdMedium:   2,
	ThresholdLow:      1,
}

// severityLevels maps Rampart severity strings to numeric levels.
var severityLevels = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     1,
}

// minSeverityReached returns true if the given severity meets the threshold.
func minSeverityReached(sev string, threshold SeverityThreshold) bool {
	sevLevel, ok := severityLevels[sev]
	if !ok {
		sevLevel = 2 // default to medium
	}
	thresholdLevel, ok := thresholdLevels[threshold]
	if !ok {
		thresholdLevel = 2
	}
	return sevLevel >= thresholdLevel
}

// Handler processes LSP document events and publishes diagnostics.
type Handler struct {
	client      *RampartClient
	debounceMs  int
	minSeverity SeverityThreshold

	mu             sync.Mutex
	documents      map[string]string // uri → full text
	debounceTimers map[string]*time.Timer
}

// NewHandler creates a new LSP handler.
func NewHandler(client *RampartClient, debounceMs int, minSeverity SeverityThreshold) *Handler {
	return &Handler{
		client:         client,
		debounceMs:     debounceMs,
		minSeverity:    minSeverity,
		documents:      make(map[string]string),
		debounceTimers: make(map[string]*time.Timer),
	}
}

// HandleDidOpen processes a textDocument/didOpen notification.
func (h *Handler) HandleDidOpen(params DidOpenTextDocumentParams) {
	h.mu.Lock()
	h.documents[params.TextDocument.URI] = params.TextDocument.Text
	h.mu.Unlock()

	h.scheduleDetect(params.TextDocument.URI, params.TextDocument.Version)
}

// HandleDidChange processes a textDocument/didChange notification.
func (h *Handler) HandleDidChange(params DidChangeTextDocumentParams) {
	// For SyncKindFull, the last content change contains the full text.
	if len(params.ContentChanges) > 0 {
		text := params.ContentChanges[len(params.ContentChanges)-1].Text
		h.mu.Lock()
		h.documents[params.TextDocument.URI] = text
		h.mu.Unlock()
	}

	h.scheduleDetect(params.TextDocument.URI, params.TextDocument.Version)
}

// GetDocument returns the current text for a URI.
func (h *Handler) GetDocument(uri string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	text, ok := h.documents[uri]
	return text, ok
}

// scheduleDetect debounces detect calls after text changes.
// After debounceMs milliseconds of silence, it calls /detect and publishes diagnostics.
func (h *Handler) scheduleDetect(uri string, version int) {
	h.mu.Lock()
	if timer, ok := h.debounceTimers[uri]; ok {
		timer.Stop()
	}
	h.debounceTimers[uri] = time.AfterFunc(time.Duration(h.debounceMs)*time.Millisecond, func() {
		h.detectAndPublish(uri, version)
	})
	h.mu.Unlock()
}

// detectAndPublish calls /detect for the document and returns diagnostics
// for the server to forward to the client as textDocument/publishDiagnostics.
func (h *Handler) detectAndPublish(uri string, version int) []Diagnostic {
	h.mu.Lock()
	text, ok := h.documents[uri]
	h.mu.Unlock()

	if !ok || text == "" {
		return nil
	}

	summary, err := h.client.Detect(context.Background(), text)
	if err != nil {
		log.Printf("rampart-lsp: detect error for %s: %v", uri, err)
		return nil
	}

	return convertDiagnostics(summary, h.minSeverity)
}

// DetectAndPublish is the exported version for use by the server.
func (h *Handler) DetectAndPublish(uri string, version int) []Diagnostic {
	return h.detectAndPublish(uri, version)
}

// ScheduleDetect is the exported version for use by the server.
func (h *Handler) ScheduleDetect(uri string, version int) {
	h.scheduleDetect(uri, version)
}

// convertDiagnostics transforms Rampart detection results into LSP diagnostics.
func convertDiagnostics(summary *DetectSummary, minSeverity SeverityThreshold) []Diagnostic {
	var diagnostics []Diagnostic

	for _, result := range summary.Results {
		if !minSeverityReached(result.Severity, minSeverity) {
			continue
		}

		sev, ok := severityOrder[result.Severity]
		if !ok {
			sev = SeverityWarning
		}

		icon := categoryIcons[result.Category]
		if icon == "" {
			icon = categoryIcons[result.Rule]
		}

		msg := formatDiagnosticMessage(icon, result)
		msg = strings.TrimSpace(msg)

		diag := Diagnostic{
			Range: Range{
				Start: Position{Line: 0, Character: 0},
				End:   Position{Line: 0, Character: 0},
			},
			Severity: sev,
			Code:     result.Rule,
			Source:   "rampart",
			Message:  msg,
		}

		diagnostics = append(diagnostics, diag)
	}

	return diagnostics
}

// formatDiagnosticMessage creates the display message for a diagnostic.
func formatDiagnosticMessage(icon string, result DetectResult) string {
	if icon != "" && result.Text != "" {
		return fmt.Sprintf("%s %s", icon, result.Text)
	}
	if icon != "" {
		return fmt.Sprintf("%s %s detection", icon, result.Category)
	}
	if result.Text != "" {
		return result.Text
	}
	return fmt.Sprintf("%s detection", result.Category)
}
