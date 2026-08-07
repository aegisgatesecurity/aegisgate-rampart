// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — LSP Server Coverage Tests
// =========================================================================

package lsp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// threadSafeBuffer wraps bytes.Buffer with a mutex for safe concurrent access.
type threadSafeBuffer struct {
	mu  sync.RWMutex
	buf bytes.Buffer
}

func (b *threadSafeBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *threadSafeBuffer) String() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.buf.String()
}

func TestNewServer(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)
	s := NewServer(handler)
	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if s.handler == nil {
		t.Error("expected handler to be set")
	}
}

func TestRunInitializeAndExit(t *testing.T) {
	summary := &DetectSummary{TotalDetections: 0}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	handler := NewHandler(client, 300, ThresholdMedium)

	var inBuf bytes.Buffer
	id := 1
	inBuf.Write(writeRPCMessage(&Message{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "initialize",
		Params:  json.RawMessage(`{"processId":1,"rootUri":"file:///tmp","capabilities":{}}`),
	}))
	inBuf.Write(writeRPCMessage(&Message{
		JSONRPC: "2.0",
		Method:  "exit",
	}))

	var outBuf bytes.Buffer
	s := NewServerWithIO(handler, &inBuf, &outBuf)

	err := s.Run()
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, `"jsonrpc":"2.0"`) {
		t.Error("expected jsonrpc response in output")
	}
	if !strings.Contains(output, "textDocumentSync") {
		t.Error("expected textDocumentSync capability in response")
	}
}

func TestRunEOF(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	s := NewServerWithIO(handler, strings.NewReader(""), &bytes.Buffer{})
	err := s.Run()
	if err != nil {
		t.Errorf("expected nil error on EOF, got: %v", err)
	}
}

func TestServerHandleDidOpenSync(t *testing.T) {
	summary := &DetectSummary{
		TotalDetections: 1,
		Results: []DetectResult{
			{Category: "secrets", Severity: "high", Text: "AWS key", Rule: "secret_aws_key"},
		},
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	}))
	defer hs.Close()

	client := NewRampartClient(hs.URL)
	handler := NewHandler(client, 10, ThresholdMedium)

	var outBuf threadSafeBuffer
	s := NewServerWithIO(handler, strings.NewReader(""), &outBuf)

	params := json.RawMessage(`{"textDocument":{"uri":"file:///test.py","languageId":"python","version":1,"text":"AKIAIOSFODNN7EXAMPLE"}}`)
	msg := &Message{
		JSONRPC: "2.0",
		Method:  "textDocument/didOpen",
		Params:  params,
	}

	s.dispatch(msg)

	// Wait for goroutine
	time.Sleep(200 * time.Millisecond)

	output := outBuf.String()
	if !strings.Contains(output, "textDocument/publishDiagnostics") {
		t.Errorf("expected publishDiagnostics notification, got: %s", output[:min(len(output), 200)])
	}
	if !strings.Contains(output, "file:///test.py") {
		t.Error("expected URI in diagnostics")
	}
}

func TestServerHandleDidChangeSync(t *testing.T) {
	summary := &DetectSummary{
		TotalDetections: 1,
		Results: []DetectResult{
			{Category: "pii", Severity: "medium", Text: "SSN", Rule: "pii_ssn"},
		},
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	}))
	defer hs.Close()

	client := NewRampartClient(hs.URL)
	handler := NewHandler(client, 10, ThresholdMedium)

	var outBuf threadSafeBuffer
	s := NewServerWithIO(handler, strings.NewReader(""), &outBuf)

	params := json.RawMessage(`{"textDocument":{"uri":"file:///test.py","version":2},"contentChanges":[{"text":"555-55-5555"}]}`)
	msg := &Message{
		JSONRPC: "2.0",
		Method:  "textDocument/didChange",
		Params:  params,
	}

	s.dispatch(msg)

	// Wait for debounce + detect + publish
	time.Sleep(300 * time.Millisecond)

	output := outBuf.String()
	if !strings.Contains(output, "textDocument/publishDiagnostics") {
		t.Errorf("expected publishDiagnostics notification, got: %s", output[:min(len(output), 200)])
	}
}

func TestHandleDidOpenBadParams(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	s := NewServerWithIO(handler, strings.NewReader(""), &bytes.Buffer{})

	msg := &Message{
		JSONRPC: "2.0",
		Method:  "textDocument/didOpen",
		Params:  json.RawMessage(`{bad json`),
	}

	result := s.dispatch(msg)
	if result != nil {
		t.Error("expected nil response for didOpen notification")
	}
}

func TestHandleDidChangeBadParams(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	s := NewServerWithIO(handler, strings.NewReader(""), &bytes.Buffer{})

	msg := &Message{
		JSONRPC: "2.0",
		Method:  "textDocument/didChange",
		Params:  json.RawMessage(`{bad json`),
	}

	result := s.dispatch(msg)
	if result != nil {
		t.Error("expected nil response for didChange notification")
	}
}

func TestDispatchInitialized(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)
	s := NewServerWithIO(handler, strings.NewReader(""), &bytes.Buffer{})

	result := s.dispatch(&Message{JSONRPC: "2.0", Method: "initialized"})
	if result != nil {
		t.Error("expected nil response for initialized notification")
	}
}

func TestDispatchUnknownNotification(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)
	s := NewServerWithIO(handler, strings.NewReader(""), &bytes.Buffer{})

	result := s.dispatch(&Message{JSONRPC: "2.0", Method: "textDocument/completion"})
	if result != nil {
		t.Error("expected nil response for unknown notification")
	}
}

func TestPublishDiagnosticsDebouncedSync(t *testing.T) {
	summary := &DetectSummary{
		TotalDetections: 1,
		Results: []DetectResult{
			{Category: "secrets", Severity: "high", Text: "key", Rule: "secret_api_key"},
		},
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	}))
	defer hs.Close()

	client := NewRampartClient(hs.URL)
	handler := NewHandler(client, 10, ThresholdMedium)

	var outBuf threadSafeBuffer
	s := NewServerWithIO(handler, strings.NewReader(""), &outBuf)

	// Open doc first so handler knows about it
	handler.HandleDidOpen(DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{URI: "file:///test.py", Version: 1, Text: "AKIAIOSFODNN7EXAMPLE"},
	})

	s.publishDiagnosticsDebounced("file:///test.py", 1)

	// Wait for debounce + detect
	time.Sleep(300 * time.Millisecond)

	output := outBuf.String()
	if !strings.Contains(output, "textDocument/publishDiagnostics") {
		t.Errorf("expected publishDiagnostics after debounce, got: %s", output[:min(len(output), 200)])
	}
}

func TestSendDiagnosticsEmpty(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	var outBuf bytes.Buffer
	s := NewServerWithIO(handler, strings.NewReader(""), &outBuf)

	s.sendDiagnostics("file:///test.py", 1, nil)

	output := outBuf.String()
	if !strings.Contains(output, "textDocument/publishDiagnostics") {
		t.Error("expected publishDiagnostics notification")
	}
	if !strings.Contains(output, `"diagnostics":[]`) {
		t.Errorf("expected empty diagnostics array, got: %s", output[:min(len(output), 200)])
	}
}

func TestSendDiagnosticsWithItems(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	var outBuf bytes.Buffer
	s := NewServerWithIO(handler, strings.NewReader(""), &outBuf)

	diagnostics := []Diagnostic{
		{
			Range:    Range{Start: Position{Line: 0, Character: 0}, End: Position{Line: 0, Character: 10}},
			Severity: SeverityError,
			Code:     "secret_key",
			Source:   "rampart",
			Message:  "🔑 Secret detected",
		},
	}

	s.sendDiagnostics("file:///app.py", 3, diagnostics)

	output := outBuf.String()
	if !strings.Contains(output, "file:///app.py") {
		t.Error("expected URI in output")
	}
	if !strings.Contains(output, "secret_key") {
		t.Error("expected diagnostic code in output")
	}
	if !strings.Contains(output, `"version":3`) {
		t.Error("expected version 3 in output")
	}
}

func TestRunReadError(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	errReader := &errorReader{err: fmt.Errorf("read failure")}
	s := NewServerWithIO(handler, errReader, &bytes.Buffer{})

	err := s.Run()
	if err == nil {
		t.Error("expected error from Run()")
	}
}

type errorReader struct{ err error }

func (r *errorReader) Read(p []byte) (n int, err error) { return 0, r.err }

func TestDispatchFullFlow(t *testing.T) {
	summary := &DetectSummary{TotalDetections: 0}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	}))
	defer hs.Close()

	client := NewRampartClient(hs.URL)
	handler := NewHandler(client, 10, ThresholdMedium)

	s := NewServerWithIO(handler, strings.NewReader(""), &bytes.Buffer{})

	tests := []struct {
		name     string
		method   string
		id       int
		params   json.RawMessage
		wantResp bool
		wantErr  bool
	}{
		{name: "initialize", method: "initialize", id: 1, params: json.RawMessage(`{"processId":1}`), wantResp: true},
		{name: "initialized", method: "initialized", wantResp: false},
		{name: "shutdown", method: "shutdown", id: 2, wantResp: true},
		{name: "unknown with id", method: "custom/method", id: 3, wantResp: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &Message{JSONRPC: "2.0", Method: tt.method}
			if tt.id != 0 {
				id := tt.id
				msg.ID = &id
			}
			if tt.params != nil {
				msg.Params = tt.params
			}

			resp := s.dispatch(msg)
			if tt.wantResp && resp == nil {
				t.Error("expected response, got nil")
			}
			if !tt.wantResp && resp != nil {
				t.Errorf("expected nil response, got: %+v", resp)
			}
			if tt.wantErr && (resp == nil || resp.Error == nil) {
				t.Error("expected error response")
			}
		})
	}
}

func TestReadMessageInvalidJSON(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	input := "Content-Length: 5\r\n\r\nhello"
	s := NewServerWithIO(handler, strings.NewReader(input), &bytes.Buffer{})

	_, err := s.readMessage()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestReadMessageTruncatedBody(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	input := "Content-Length: 100\r\n\r\nshort"
	s := NewServerWithIO(handler, strings.NewReader(input), &bytes.Buffer{})

	_, err := s.readMessage()
	if err == nil {
		t.Error("expected error for truncated body")
	}
}

func TestPublishDiagnosticsDirect(t *testing.T) {
	summary := &DetectSummary{
		TotalDetections: 2,
		Results: []DetectResult{
			{Category: "secrets", Severity: "high", Text: "AWS key", Rule: "secret_aws_key"},
			{Category: "pii", Severity: "medium", Text: "SSN", Rule: "pii_ssn"},
		},
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	}))
	defer hs.Close()

	client := NewRampartClient(hs.URL)
	handler := NewHandler(client, 10, ThresholdMedium)

	var outBuf bytes.Buffer
	s := NewServerWithIO(handler, strings.NewReader(""), &outBuf)

	handler.HandleDidOpen(DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{URI: "file:///test.py", Version: 1, Text: "AKIAIOSFODNN7EXAMPLE\n555-55-5555"},
	})

	// Direct (non-goroutine) call — no race
	s.publishDiagnostics("file:///test.py", 1)

	output := outBuf.String()
	if !strings.Contains(output, "textDocument/publishDiagnostics") {
		t.Error("expected publishDiagnostics notification")
	}
	if !strings.Contains(output, "secret_aws_key") {
		t.Error("expected secret_aws_key in diagnostics")
	}
}

func TestWriteMessageError(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	errWriter := &errorWriter{}
	s := NewServerWithIO(handler, strings.NewReader(""), errWriter)

	id := 1
	msg := &Message{JSONRPC: "2.0", ID: &id, Result: json.RawMessage(`{}`)}

	err := s.writeMessage(msg)
	if err == nil {
		t.Error("expected write error")
	}
}

type errorWriter struct{}

func (w *errorWriter) Write(p []byte) (n int, err error) { return 0, fmt.Errorf("write error") }

func TestRunFullPipeline(t *testing.T) {
	summary := &DetectSummary{
		TotalDetections: 1,
		Results: []DetectResult{
			{Category: "secrets", Severity: "high", Text: "AWS key found", Rule: "secret_aws_key"},
		},
	}
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	}))
	defer hs.Close()

	client := NewRampartClient(hs.URL)
	handler := NewHandler(client, 10, ThresholdLow)

	// initialize → didOpen → shutdown → exit
	var inBuf bytes.Buffer
	id1 := 1
	inBuf.Write(writeRPCMessage(&Message{
		JSONRPC: "2.0", ID: &id1, Method: "initialize",
		Params: json.RawMessage(`{"processId":1}`),
	}))
	inBuf.Write(writeRPCMessage(&Message{
		JSONRPC: "2.0", Method: "textDocument/didOpen",
		Params: json.RawMessage(`{"textDocument":{"uri":"file:///test.py","languageId":"python","version":1,"text":"AKIAIOSFODNN7EXAMPLE"}}`),
	}))
	id2 := 2
	inBuf.Write(writeRPCMessage(&Message{
		JSONRPC: "2.0", ID: &id2, Method: "shutdown",
	}))
	inBuf.Write(writeRPCMessage(&Message{
		JSONRPC: "2.0", Method: "exit",
	}))

	var outBuf threadSafeBuffer
	s := NewServerWithIO(handler, &inBuf, &outBuf)

	err := s.Run()
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	output := outBuf.String()
	// Verify initialize and shutdown responses (didOpen diagnostics may not be written yet due to goroutine)
	if !strings.Contains(output, `"id":1`) {
		t.Error("expected initialize response with id 1")
	}
	if !strings.Contains(output, `"id":2`) {
		t.Error("expected shutdown response with id 2")
	}
	if !strings.Contains(output, "textDocumentSync") {
		t.Error("expected textDocumentSync in capabilities")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
