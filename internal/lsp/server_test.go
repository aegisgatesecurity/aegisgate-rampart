// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — LSP Server Tests
// =========================================================================

package lsp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// writeRPCMessage writes a JSON-RPC message with Content-Length header.
func writeRPCMessage(msg *Message) []byte {
	body, _ := json.Marshal(msg)
	return []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body))
}

func TestServerInitialize(t *testing.T) {
	summary := &DetectSummary{TotalDetections: 0}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	handler := NewHandler(client, 300, ThresholdMedium)

	var inBuf bytes.Buffer
	var outBuf bytes.Buffer

	s := NewServerWithIO(handler, &inBuf, &outBuf)

	id := 1
	initMsg := &Message{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "initialize",
		Params:  json.RawMessage(`{"processId":1,"rootUri":"file:///tmp","capabilities":{}}`),
	}

	msgBytes := writeRPCMessage(initMsg)
	inBuf.Write(msgBytes)

	// Read and process one message
	resp, err := s.readMessage()
	if err != nil {
		t.Fatalf("readMessage error: %v", err)
	}

	response := s.dispatch(resp)
	if response == nil {
		t.Fatal("expected response, got nil")
	}

	// Verify response structure
	if response.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", response.JSONRPC)
	}
	if response.ID == nil || *response.ID != 1 {
		t.Error("expected response id 1")
	}

	// Parse result
	var result InitializeResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if result.Capabilities.TextDocumentSync == nil {
		t.Error("expected TextDocumentSync capability")
	}
	if result.Capabilities.TextDocumentSync.Change != SyncKindFull {
		t.Errorf("expected SyncKindFull, got %d", result.Capabilities.TextDocumentSync.Change)
	}
}

func TestServerShutdown(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	var inBuf bytes.Buffer
	var outBuf bytes.Buffer

	s := NewServerWithIO(handler, &inBuf, &outBuf)

	id := 1
	shutdownMsg := &Message{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "shutdown",
	}

	response := s.dispatch(shutdownMsg)
	if response == nil {
		t.Fatal("expected response, got nil")
	}
	if response.Error != nil {
		t.Errorf("expected no error, got %v", response.Error)
	}
}

func TestServerUnknownMethod(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	s := NewServerWithIO(handler, &strings.Reader{}, &bytes.Buffer{})

	id := 42
	msg := &Message{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "textDocument/hover",
	}

	response := s.dispatch(msg)
	if response == nil {
		t.Fatal("expected error response for unknown method")
	}
	if response.Error == nil {
		t.Error("expected error for unknown method")
	}
	if response.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", response.Error.Code)
	}
}

func TestServerNotificationNoResponse(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	s := NewServerWithIO(handler, &strings.Reader{}, &bytes.Buffer{})

	// Notifications (no ID) should return nil response
	msg := &Message{
		JSONRPC: "2.0",
		Method:  "initialized",
	}

	response := s.dispatch(msg)
	if response != nil {
		t.Error("expected nil response for notification")
	}
}

func TestWriteMessage(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	var outBuf bytes.Buffer
	s := NewServerWithIO(handler, &strings.Reader{}, &outBuf)

	id := 1
	msg := &Message{
		JSONRPC: "2.0",
		ID:      &id,
		Result:  json.RawMessage(`{"capabilities":{}}`),
	}

	if err := s.writeMessage(msg); err != nil {
		t.Fatalf("writeMessage error: %v", err)
	}

	output := outBuf.String()
	if !strings.HasPrefix(output, "Content-Length:") {
		t.Errorf("expected Content-Length header, got: %s", output[:50])
	}
	if !strings.Contains(output, `"jsonrpc":"2.0"`) {
		t.Errorf("expected jsonrpc in body, got: %s", output)
	}
}

func TestReadMessage(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	id := 1
	msg := &Message{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "initialize",
	}
	msgBytes := writeRPCMessage(msg)

	inBuf := bytes.NewBuffer(msgBytes)
	s := NewServerWithIO(handler, inBuf, &bytes.Buffer{})

	readMsg, err := s.readMessage()
	if err != nil {
		t.Fatalf("readMessage error: %v", err)
	}
	if readMsg.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", readMsg.JSONRPC)
	}
	if readMsg.Method != "initialize" {
		t.Errorf("expected method 'initialize', got %s", readMsg.Method)
	}
}

func TestReadMessageMissingContentLength(t *testing.T) {
	client := NewRampartClient("http://localhost:99999")
	handler := NewHandler(client, 300, ThresholdMedium)

	// No Content-Length header
	inBuf := bytes.NewBufferString("\r\n")
	s := NewServerWithIO(handler, inBuf, &bytes.Buffer{})

	_, err := s.readMessage()
	if err == nil {
		t.Error("expected error for missing Content-Length")
	}
}

func TestPublishDiagnostics(t *testing.T) {
	summary := &DetectSummary{
		TotalDetections: 1,
		Results: []DetectResult{
			{Category: "secrets", Severity: "high", Text: "AWS key", Rule: "secret_aws_key"},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	handler := NewHandler(client, 10, ThresholdMedium)

	var outBuf bytes.Buffer
	s := NewServerWithIO(handler, &strings.Reader{}, &outBuf)

	// Open document
	handler.HandleDidOpen(DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:     "file:///test.py",
			Version: 1,
			Text:    "AKIAIOSFODNN7EXAMPLE",
		},
	})

	// Manually trigger publish diagnostics
	s.sendDiagnostics("file:///test.py", 1, []Diagnostic{
		{
			Range: Range{
				Start: Position{Line: 0, Character: 0},
				End:   Position{Line: 0, Character: 18},
			},
			Severity: SeverityError,
			Code:     "secret_aws_key",
			Source:   "rampart",
			Message:  "🔑 AWS key",
		},
	})

	output := outBuf.String()
	if !strings.Contains(output, "textDocument/publishDiagnostics") {
		t.Errorf("expected publishDiagnostics in output, got: %s", output)
	}
	if !strings.Contains(output, "file:///test.py") {
		t.Errorf("expected URI in output, got: %s", output)
	}
}

func TestRoundTrip(t *testing.T) {
	// Test full round-trip: initialize → write message → read response
	summary := &DetectSummary{TotalDetections: 0}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
	}))
	defer server.Close()

	client := NewRampartClient(server.URL)
	handler := NewHandler(client, 300, ThresholdMedium)

	var outBuf bytes.Buffer
	s := NewServerWithIO(handler, io.NopCloser(strings.NewReader("")), &outBuf)

	// Write an initialize response
	id := 1
	initResult := InitializeResult{
		Capabilities: ServerCapabilities{
			TextDocumentSync: &TextDocumentSyncOptions{
				OpenClose: true,
				Change:    SyncKindFull,
			},
		},
	}
	resultBytes, _ := json.Marshal(initResult)
	msg := &Message{
		JSONRPC: "2.0",
		ID:      &id,
		Result:  resultBytes,
	}
	if err := s.writeMessage(msg); err != nil {
		t.Fatalf("writeMessage error: %v", err)
	}

	// Verify output
	output := outBuf.String()
	if !strings.HasPrefix(output, "Content-Length:") {
		t.Error("expected Content-Length header")
	}

	// Parse the message back
	reader := strings.NewReader(output)
	s2 := NewServerWithIO(handler, reader, &bytes.Buffer{})
	readMsg, err := s2.readMessage()
	if err != nil {
		t.Fatalf("failed to read back message: %v", err)
	}

	if readMsg.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", readMsg.JSONRPC)
	}
}
