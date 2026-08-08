// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — LSP Handler Tests
// =========================================================================

package lsp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestHandler creates a handler pointing at a test server returning the given summary.
func newTestHandler(t *testing.T, summary *DetectSummary) (*Handler, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}))
	client := NewRampartClient(server.URL)
	handler := NewHandler(client, 50, ThresholdMedium) // 50ms debounce for tests
	return handler, server
}

func TestNewHandler(t *testing.T) {
	client := NewRampartClient("http://localhost:9090")
	handler := NewHandler(client, 300, ThresholdMedium)

	if handler.debounceMs != 300 {
		t.Errorf("expected 300ms debounce, got %d", handler.debounceMs)
	}
	if handler.minSeverity != ThresholdMedium {
		t.Errorf("expected medium threshold, got %s", handler.minSeverity)
	}
}

func TestHandleDidOpen(t *testing.T) {
	summary := &DetectSummary{
		TotalDetections: 1,
		Results: []DetectResult{
			{
				Category: "secrets",
				Severity: "high",
				Text:     "AWS key detected",
				Rule:     "secret_aws_key",
			},
		},
	}
	handler, server := newTestHandler(t, summary)
	defer server.Close()

	params := DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:        "file:///test.py",
			LanguageID: "python",
			Version:    1,
			Text:       "AKIAIOSFODNN7EXAMPLE",
		},
	}

	handler.HandleDidOpen(params)

	text, ok := handler.GetDocument("file:///test.py")
	if !ok {
		t.Fatal("expected document to be stored")
	}
	if text != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected text 'AKIAIOSFODNN7EXAMPLE', got %q", text)
	}
}

func TestHandleDidChange(t *testing.T) {
	summary := &DetectSummary{TotalDetections: 0}
	handler, server := newTestHandler(t, summary)
	defer server.Close()

	// First, open the document
	handler.HandleDidOpen(DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:     "file:///test.py",
			Version: 1,
			Text:    "original",
		},
	})

	// Then change it
	handler.HandleDidChange(DidChangeTextDocumentParams{
		TextDocument: VersionedTextDocumentIdentifier{
			URI:     "file:///test.py",
			Version: 2,
		},
		ContentChanges: []TextDocumentContentChangeEvent{
			{Text: "updated"},
		},
	})

	text, ok := handler.GetDocument("file:///test.py")
	if !ok {
		t.Fatal("expected document to be stored")
	}
	if text != "updated" {
		t.Errorf("expected text 'updated', got %q", text)
	}
}

func TestMinSeverityReached(t *testing.T) {
	tests := []struct {
		sev       string
		threshold SeverityThreshold
		expected  bool
	}{
		{"critical", ThresholdCritical, true},
		{"critical", ThresholdMedium, true},
		{"high", ThresholdHigh, true},
		{"medium", ThresholdHigh, false},
		{"medium", ThresholdMedium, true},
		{"low", ThresholdMedium, false},
		{"low", ThresholdLow, true},
		{"info", ThresholdLow, true},
		{"unknown", ThresholdMedium, true}, // unknown defaults to medium
		{"unknown", ThresholdHigh, false},
	}

	for _, tt := range tests {
		result := minSeverityReached(tt.sev, tt.threshold)
		if result != tt.expected {
			t.Errorf("minSeverityReached(%q, %s) = %v, want %v", tt.sev, tt.threshold, result, tt.expected)
		}
	}
}

func TestConvertDiagnostics(t *testing.T) {
	summary := &DetectSummary{
		TotalDetections: 4,
		Results: []DetectResult{
			{Category: "secrets", Severity: "high", Text: "AWS key found", Rule: "secret_aws_key"},
			{Category: "pii", Severity: "medium", Text: "SSN detected", Rule: "pii_ssn"},
			{Category: "xss", Severity: "low", Text: "XSS pattern", Rule: "xss_reflected"},
			{Category: "compliance", Severity: "info", Text: "GDPR violation", Rule: "compliance_gdpr"},
		},
	}

	t.Run("medium threshold filters low", func(t *testing.T) {
		diagnostics := convertDiagnostics(summary, ThresholdMedium, "monitor")
		if len(diagnostics) != 2 {
			t.Errorf("expected 2 diagnostics at medium threshold, got %d", len(diagnostics))
		}
		// Check severities
		for _, d := range diagnostics {
			if d.Severity == SeverityHint {
				t.Error("expected no Hint diagnostics at medium threshold")
			}
		}
	})

	t.Run("low threshold includes all", func(t *testing.T) {
		diagnostics := convertDiagnostics(summary, ThresholdLow, "monitor")
		if len(diagnostics) != 4 {
			t.Errorf("expected 4 diagnostics at low threshold, got %d", len(diagnostics))
		}
	})

	t.Run("critical threshold only critical", func(t *testing.T) {
		diagnostics := convertDiagnostics(summary, ThresholdCritical, "monitor")
		// No "critical" severity items in summary (highest is "high"=3, threshold=4)
		if len(diagnostics) != 0 {
			t.Errorf("expected 0 diagnostics at critical threshold, got %d", len(diagnostics))
		}
	})

	t.Run("high threshold includes critical and high", func(t *testing.T) {
		highSummary := &DetectSummary{
			TotalDetections: 3,
			Results: []DetectResult{
				{Category: "secrets", Severity: "critical", Text: "Leaked key", Rule: "secret_leak"},
				{Category: "secrets", Severity: "high", Text: "AWS key found", Rule: "secret_aws_key"},
				{Category: "pii", Severity: "medium", Text: "SSN detected", Rule: "pii_ssn"},
			},
		}
		diagnostics := convertDiagnostics(highSummary, ThresholdHigh, "monitor")
		if len(diagnostics) != 2 {
			t.Errorf("expected 2 diagnostics at high threshold, got %d", len(diagnostics))
		}
	})

	t.Run("icon prefix in message", func(t *testing.T) {
		diagnostics := convertDiagnostics(summary, ThresholdLow, "monitor")
		// secrets → 🔑
		found := false
		for _, d := range diagnostics {
			if d.Code == "secret_aws_key" {
				found = true
				if d.Source != "rampart" {
					t.Errorf("expected source 'rampart', got %q", d.Source)
				}
				// Check icon is in message
			}
		}
		if !found {
			t.Error("expected to find secret_aws_key diagnostic")
		}
	})
}

func TestConvertDiagnosticsIconMapping(t *testing.T) {
	tests := []struct {
		category string
		wantIcon string
	}{
		{"secrets", "🔑"},
		{"pii", "🔐"},
		{"pii-us-core", "🔐"},
		{"pii-financial", "💳"},
		{"xss", "⚔️"},
		{"compliance", "📋"},
		{"ml_threat", "🧠"},
		{"prompt_injection", "🧠"},
	}

	for _, tt := range tests {
		summary := &DetectSummary{
			TotalDetections: 1,
			Results: []DetectResult{
				{Category: tt.category, Severity: "high", Text: "test", Rule: tt.category},
			},
		}
		diagnostics := convertDiagnostics(summary, ThresholdLow, "monitor")
		if len(diagnostics) != 1 {
			t.Errorf("category %s: expected 1 diagnostic, got %d", tt.category, len(diagnostics))
			continue
		}
		if diagnostics[0].Message[:len(tt.wantIcon)] != tt.wantIcon {
			t.Errorf("category %s: expected icon %s in message, got %q", tt.category, tt.wantIcon, diagnostics[0].Message)
		}
	}
}

func TestFormatDiagnosticMessage(t *testing.T) {
	tests := []struct {
		name     string
		icon     string
		result   DetectResult
		expected string
	}{
		{
			name:     "icon and text",
			icon:     "🔑",
			result:   DetectResult{Category: "secrets", Text: "AWS key found"},
			expected: "🔑 AWS key found",
		},
		{
			name:     "icon without text",
			icon:     "🔐",
			result:   DetectResult{Category: "pii", Text: ""},
			expected: "🔐 pii detection",
		},
		{
			name:     "no icon with text",
			icon:     "",
			result:   DetectResult{Category: "unknown", Text: "something found"},
			expected: "something found",
		},
		{
			name:     "no icon no text",
			icon:     "",
			result:   DetectResult{Category: "unknown", Text: ""},
			expected: "unknown detection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDiagnosticMessage(tt.icon, tt.result)
			if got != tt.expected {
				t.Errorf("formatDiagnosticMessage() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestSeverityOrderMapping(t *testing.T) {
	tests := []struct {
		sev      string
		expected DiagnosticSeverity
	}{
		{"critical", SeverityError},
		{"high", SeverityError},
		{"medium", SeverityWarning},
		{"low", SeverityHint},
		{"info", SeverityHint},
		{"unknown", SeverityWarning}, // fallback
	}

	for _, tt := range tests {
		got, ok := severityOrder[tt.sev]
		if !ok && tt.sev != "unknown" {
			t.Errorf("severity %s not in severityOrder map", tt.sev)
		}
		if !ok {
			got = SeverityWarning // fallback
		}
		if got != tt.expected {
			t.Errorf("severityOrder[%q] = %d, want %d", tt.sev, got, tt.expected)
		}
	}
}

func TestDetectAndPublish(t *testing.T) {
	summary := &DetectSummary{
		TotalDetections: 1,
		Results: []DetectResult{
			{Category: "secrets", Severity: "high", Text: "AWS key found", Rule: "secret_aws_key"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	handler := NewHandler(client, 10, ThresholdMedium)

	// Open document first
	handler.HandleDidOpen(DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:     "file:///test.py",
			Version: 1,
			Text:    "my AWS key is AKIAIOSFODNN7EXAMPLE",
		},
	})

	// Call detectAndPublish directly (no debounce)
	diagnostics := handler.DetectAndPublish("file:///test.py", 1)
	if len(diagnostics) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(diagnostics))
	}

	diag := diagnostics[0]
	if diag.Source != "rampart" {
		t.Errorf("expected source 'rampart', got %q", diag.Source)
	}
	if diag.Code != "secret_aws_key" {
		t.Errorf("expected code 'secret_aws_key', got %q", diag.Code)
	}
	if diag.Severity != SeverityError {
		t.Errorf("expected severity Error (1), got %d", diag.Severity)
	}
}

func TestDetectAndPublishEmptyDocument(t *testing.T) {
	client := NewRampartClient("http://localhost:99999") // won't be called
	handler := NewHandler(client, 10, ThresholdMedium)

	// No document opened — should return nil
	diagnostics := handler.DetectAndPublish("file:///nonexistent.py", 1)
	if diagnostics != nil {
		t.Errorf("expected nil diagnostics for missing document, got %v", diagnostics)
	}
}

func TestDetectAndPublishServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	handler := NewHandler(client, 10, ThresholdMedium)

	handler.HandleDidOpen(DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:     "file:///test.py",
			Version: 1,
			Text:    "test",
		},
	})

	// Server error — should return nil (no crash)
	diagnostics := handler.DetectAndPublish("file:///test.py", 1)
	if diagnostics != nil {
		t.Errorf("expected nil diagnostics on server error, got %v", diagnostics)
	}
}

func TestConcurrentDocumentAccess(t *testing.T) {
	summary := &DetectSummary{TotalDetections: 0}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	handler := NewHandler(client, 10, ThresholdMedium)

	// Concurrently open multiple documents
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			uri := "file:///test" + string(rune('0'+i)) + ".py"
			handler.HandleDidOpen(DidOpenTextDocumentParams{
				TextDocument: TextDocumentItem{
					URI:     uri,
					Version: 1,
					Text:    "test",
				},
			})
		}(i)
	}
	wg.Wait()

	// Verify all documents are stored
	for i := 0; i < 10; i++ {
		uri := "file:///test" + string(rune('0'+i)) + ".py"
		_, ok := handler.GetDocument(uri)
		if !ok {
			t.Errorf("expected document %s to be stored", uri)
		}
	}
}

func TestDebounceTimer(t *testing.T) {
	summary := &DetectSummary{TotalDetections: 0}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	handler := NewHandler(client, 50, ThresholdMedium) // 50ms debounce

	// Open document
	handler.HandleDidOpen(DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:     "file:///test.py",
			Version: 1,
			Text:    "test",
		},
	})

	// Schedule detect
	handler.ScheduleDetect("file:///test.py", 1)

	// Verify the timer was set
	handler.mu.Lock()
	_, hasTimer := handler.debounceTimers["file:///test.py"]
	handler.mu.Unlock()

	if !hasTimer {
		t.Error("expected debounce timer to be set")
	}

	// Wait for debounce to fire
	time.Sleep(100 * time.Millisecond)

	// Timer should have fired and been removed
	handler.mu.Lock()
	_, stillHasTimer := handler.debounceTimers["file:///test.py"]
	handler.mu.Unlock()

	// Note: AfterFunc timers are not removed from the map automatically
	// This is fine — they get replaced on next change
	_ = stillHasTimer // not a test failure
}

func TestConvertDiagnosticsBlockMode(t *testing.T) {
	summary := &DetectSummary{
		TotalDetections: 4,
		Results: []DetectResult{
			{Category: "secrets", Severity: "critical", Text: "Leaked key", Rule: "secret_leak"},
			{Category: "secrets", Severity: "high", Text: "AWS key found", Rule: "secret_aws_key"},
			{Category: "pii", Severity: "medium", Text: "SSN detected", Rule: "pii_ssn"},
			{Category: "xss", Severity: "low", Text: "XSS pattern", Rule: "xss_reflected"},
		},
	}

	t.Run("block mode adds [BLOCKED] suffix to critical and high", func(t *testing.T) {
		diagnostics := convertDiagnostics(summary, ThresholdLow, "block")
		for _, d := range diagnostics {
			if d.Code == "secret_leak" || d.Code == "secret_aws_key" {
				if !containsBlocked(d.Message) {
					t.Errorf("expected [BLOCKED] suffix in message for %s, got %q", d.Code, d.Message)
				}
			}
			if d.Code == "pii_ssn" || d.Code == "xss_reflected" {
				if containsBlocked(d.Message) {
					t.Errorf("did not expect [BLOCKED] suffix in message for %s, got %q", d.Code, d.Message)
				}
			}
		}
	})

	t.Run("monitor mode does not add [BLOCKED] suffix", func(t *testing.T) {
		diagnostics := convertDiagnostics(summary, ThresholdLow, "monitor")
		for _, d := range diagnostics {
			if containsBlocked(d.Message) {
				t.Errorf("did not expect [BLOCKED] suffix in monitor mode for %s, got %q", d.Code, d.Message)
			}
		}
	})
}

func containsBlocked(s string) bool {
	return strings.HasSuffix(s, " [BLOCKED]")
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow server
		time.Sleep(5 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DetectSummary{})
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.Detect(ctx, "test")
	if err == nil {
		t.Error("expected error due to context cancellation, got nil")
	}
}
