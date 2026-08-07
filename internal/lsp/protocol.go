// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — LSP Protocol Types
// =========================================================================
// Minimal LSP protocol subset for exposing Rampart diagnostics to
// LSP-capable editors (Neovim, Emacs, Sublime, Helix, etc.).
// Communication uses JSON-RPC 2.0 over stdio.
// =========================================================================

package lsp

import "encoding/json"

// ── JSON-RPC 2.0 ──────────────────────────────────────────────────────

// Message represents a JSON-RPC 2.0 message.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int            `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ── LSP Base Types ─────────────────────────────────────────────────────

// Position represents a zero-based line/character position in a document.
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range represents a span between two positions in a document.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// ── Initialize ─────────────────────────────────────────────────────────

// InitializeParams is sent from the client on initialization.
type InitializeParams struct {
	ProcessID             int                `json:"processId,omitempty"`
	RootURI               string             `json:"rootUri,omitempty"`
	Capabilities          ClientCapabilities `json:"capabilities,omitempty"`
	InitializationOptions map[string]any     `json:"initializationOptions,omitempty"`
}

// ClientCapabilities represents the client's capabilities.
type ClientCapabilities struct {
	TextDocument *TextDocumentClientCapabilities `json:"textDocument,omitempty"`
}

// TextDocumentClientCapabilities describes text document capabilities.
type TextDocumentClientCapabilities struct {
	Synchronization *TextDocumentSyncClientCapabilities `json:"synchronization,omitempty"`
}

// TextDocumentSyncClientCapabilities describes sync capabilities.
type TextDocumentSyncClientCapabilities struct {
	DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
}

// InitializeResult is the server's response to initialize.
type InitializeResult struct {
	Capabilities ServerCapabilities `json:"capabilities"`
}

// ServerCapabilities describes what the server can do.
type ServerCapabilities struct {
	TextDocumentSync *TextDocumentSyncOptions `json:"textDocumentSync,omitempty"`
}

// TextDocumentSyncOptions describes how documents are synced.
type TextDocumentSyncOptions struct {
	OpenClose bool                 `json:"openClose,omitempty"`
	Change    TextDocumentSyncKind `json:"change,omitempty"`
}

// TextDocumentSyncKind defines how document changes are sent.
type TextDocumentSyncKind int

const (
	SyncKindNone        TextDocumentSyncKind = 0
	SyncKindFull        TextDocumentSyncKind = 1
	SyncKindIncremental TextDocumentSyncKind = 2
)

// ── Text Document Identifier ───────────────────────────────────────────

// TextDocumentIdentifier identifies a text document by URI.
type TextDocumentIdentifier struct {
	URI string `json:"uri"`
}

// VersionedTextDocumentIdentifier identifies a document with a version.
type VersionedTextDocumentIdentifier struct {
	URI     string `json:"uri"`
	Version int    `json:"version,omitempty"`
}

// TextDocumentItem represents a newly opened text document.
type TextDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

// ── Document Events ────────────────────────────────────────────────────

// DidOpenTextDocumentParams is sent when a document is opened.
type DidOpenTextDocumentParams struct {
	TextDocument TextDocumentItem `json:"textDocument"`
}

// DidChangeTextDocumentParams is sent when a document changes.
type DidChangeTextDocumentParams struct {
	TextDocument   VersionedTextDocumentIdentifier  `json:"textDocument"`
	ContentChanges []TextDocumentContentChangeEvent `json:"contentChanges"`
}

// TextDocumentContentChangeEvent describes a change to a document.
type TextDocumentContentChangeEvent struct {
	Range       *Range `json:"range,omitempty"`
	RangeLength int    `json:"rangeLength,omitempty"`
	Text        string `json:"text"`
}

// ── Diagnostics ────────────────────────────────────────────────────────

// DiagnosticSeverity maps to LSP diagnostic severity levels.
type DiagnosticSeverity int

const (
	SeverityError       DiagnosticSeverity = 1
	SeverityWarning     DiagnosticSeverity = 2
	SeverityInformation DiagnosticSeverity = 3
	SeverityHint        DiagnosticSeverity = 4
)

// DiagnosticRelatedInformation provides extra context for a diagnostic.
type DiagnosticRelatedInformation struct {
	Location Location `json:"location"`
	Message  string   `json:"message"`
}

// Location represents a location in a document.
type Location struct {
	URI   string `json:"uri"`
	Range Range  `json:"range"`
}

// Diagnostic represents a single diagnostic item.
type Diagnostic struct {
	Range              Range                          `json:"range"`
	Severity           DiagnosticSeverity             `json:"severity,omitempty"`
	Code               string                         `json:"code,omitempty"`
	Source             string                         `json:"source,omitempty"`
	Message            string                         `json:"message"`
	RelatedInformation []DiagnosticRelatedInformation `json:"relatedInformation,omitempty"`
	Tags               []DiagnosticTag                `json:"tags,omitempty"`
}

// DiagnosticTag represents a diagnostic tag.
type DiagnosticTag int

const (
	TagUnnecessary DiagnosticTag = 1
	TagDeprecated  DiagnosticTag = 2
)

// PublishDiagnosticsParams is sent from server to client to publish diagnostics.
type PublishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Version     int          `json:"version,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}
