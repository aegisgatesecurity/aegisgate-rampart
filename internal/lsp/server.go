// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — LSP Server
// =========================================================================
// Read JSON-RPC from stdin, dispatch to handler, write to stdout.
// Implements the minimal LSP subset needed for diagnostic publishing.
// =========================================================================

package lsp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Server implements a minimal LSP server communicating over stdio.
type Server struct {
	handler *Handler
	out     io.Writer
	in      *bufio.Reader

	mu      sync.Mutex
	running bool
}

// NewServer creates a new LSP server with the given handler.
func NewServer(handler *Handler) *Server {
	s := &Server{
		handler: handler,
		out:     os.Stdout,
		in:      bufio.NewReader(os.Stdin),
	}
	handler.OnDiagnostics = func(uri string, version int, diagnostics []Diagnostic) {
		s.sendDiagnostics(uri, version, diagnostics)
	}
	return s
}

// NewServerWithIO creates a new LSP server with custom IO (for testing).
func NewServerWithIO(handler *Handler, in io.Reader, out io.Writer) *Server {
	s := &Server{
		handler: handler,
		out:     out,
		in:      bufio.NewReader(in),
	}
	// Wire handler's OnDiagnostics callback to send diagnostics to the client.
	handler.OnDiagnostics = func(uri string, version int, diagnostics []Diagnostic) {
		s.sendDiagnostics(uri, version, diagnostics)
	}
	return s
}

// Run starts the LSP server's read-dispatch-write loop.
// Blocks until exit or error.
func (s *Server) Run() error {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	for {
		msg, err := s.readMessage()
		if err != nil {
			// EOF means client disconnected — normal shutdown.
			if err == io.EOF {
				return nil
			}
			log.Printf("rampart-lsp: read error: %v", err)
			return err
		}

		if msg == nil {
			continue
		}

		response := s.dispatch(msg)
		if response != nil {
			if err := s.writeMessage(response); err != nil {
				log.Printf("rampart-lsp: write error: %v", err)
				return err
			}
		}
	}
}

// readMessage reads a single JSON-RPC message from stdin.
func (s *Server) readMessage() (*Message, error) {
	// Read Content-Length header
	var contentLength int
	for {
		line, err := s.in.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			// Empty line signals end of headers
			break
		}
		if strings.HasPrefix(line, "Content-Length:") {
			_, after, ok := strings.Cut(line, ":")
			if ok {
				n, err := strconv.Atoi(strings.TrimSpace(after))
				if err != nil {
					return nil, fmt.Errorf("invalid Content-Length: %w", err)
				}
				contentLength = n
			}
		}
	}

	if contentLength <= 0 {
		return nil, fmt.Errorf("missing or invalid Content-Length header")
	}

	// Read JSON body
	buf := make([]byte, contentLength)
	if _, err := io.ReadFull(s.in, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var msg Message
	if err := json.Unmarshal(buf, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal message: %w", err)
	}

	return &msg, nil
}

// dispatch routes an incoming message to the appropriate handler.
func (s *Server) dispatch(msg *Message) *Message {
	switch msg.Method {
	case "initialize":
		return s.handleInitialize(msg)
	case "initialized":
		// Notification, no response needed
		return nil
	case "textDocument/didOpen":
		s.handleDidOpen(msg)
		return nil
	case "textDocument/didChange":
		s.handleDidChange(msg)
		return nil
	case "shutdown":
		return s.handleShutdown(msg)
	case "exit":
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		return nil
	default:
		// Unknown method — respond with MethodNotFound if this was a request.
		if msg.ID != nil {
			return &Message{
				JSONRPC: "2.0",
				ID:      msg.ID,
				Error: &RPCError{
					Code:    -32601,
					Message: fmt.Sprintf("method not found: %s", msg.Method),
				},
			}
		}
		return nil
	}
}

// handleInitialize responds to the initialize request with server capabilities.
func (s *Server) handleInitialize(msg *Message) *Message {
	result := InitializeResult{
		Capabilities: ServerCapabilities{
			TextDocumentSync: &TextDocumentSyncOptions{
				OpenClose: true,
				Change:    SyncKindFull,
			},
		},
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return &Message{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error:   &RPCError{Code: -32603, Message: "internal error"},
		}
	}

	return &Message{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  resultBytes,
	}
}

// handleDidOpen processes a textDocument/didOpen notification.
func (s *Server) handleDidOpen(msg *Message) {
	var params DidOpenTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		log.Printf("rampart-lsp: failed to parse didOpen params: %v", err)
		return
	}

	s.handler.HandleDidOpen(params)

	// Immediately detect and publish diagnostics
	go s.publishDiagnostics(params.TextDocument.URI, params.TextDocument.Version)
}

// handleDidChange processes a textDocument/didChange notification.
func (s *Server) handleDidChange(msg *Message) {
	var params DidChangeTextDocumentParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		log.Printf("rampart-lsp: failed to parse didChange params: %v", err)
		return
	}

	s.handler.HandleDidChange(params)
	// Debounce is handled inside the handler
	go s.publishDiagnosticsDebounced(params.TextDocument.URI, params.TextDocument.Version)
}

// handleShutdown responds to the shutdown request.
func (s *Server) handleShutdown(msg *Message) *Message {
	return &Message{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  json.RawMessage(`null`),
	}
}

// publishDiagnostics immediately detects and sends diagnostics.
func (s *Server) publishDiagnostics(uri string, version int) {
	diagnostics := s.handler.DetectAndPublish(uri, version)
	s.sendDiagnostics(uri, version, diagnostics)
}

// publishDiagnosticsDebounced uses the handler's debounce timer.
func (s *Server) publishDiagnosticsDebounced(uri string, version int) {
	// The handler's debounce timer will fire and call detectAndPublish.
	// We need to capture the result and send it.
	// For simplicity in this minimal implementation, we use the debounce timer
	// in the handler and then send the result.
	s.handler.ScheduleDetect(uri, version)
}

// sendDiagnostics publishes a textDocument/publishDiagnostics notification.
func (s *Server) sendDiagnostics(uri string, version int, diagnostics []Diagnostic) {
	if diagnostics == nil {
		diagnostics = []Diagnostic{}
	}

	params := PublishDiagnosticsParams{
		URI:         uri,
		Version:     version,
		Diagnostics: diagnostics,
	}

	paramsBytes, err := json.Marshal(params)
	if err != nil {
		log.Printf("rampart-lsp: failed to marshal diagnostics params: %v", err)
		return
	}

	notification := &Message{
		JSONRPC: "2.0",
		Method:  "textDocument/publishDiagnostics",
		Params:  paramsBytes,
	}

	if err := s.writeMessage(notification); err != nil {
		log.Printf("rampart-lsp: failed to write diagnostics notification: %v", err)
	}
}

// writeMessage writes a JSON-RPC message to stdout with Content-Length header.
func (s *Server) writeMessage(msg *Message) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	if _, err := fmt.Fprint(s.out, header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := s.out.Write(body); err != nil {
		return fmt.Errorf("write body: %w", err)
	}

	return nil
}
