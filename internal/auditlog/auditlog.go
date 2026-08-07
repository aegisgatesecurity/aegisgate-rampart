// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Audit Logger
// =========================================================================
//
// Persists every detection event to a local JSONL file for compliance and
// forensics. Stats survive restart. Files are rotated by size.
//
// Privacy (12 non-negotiables):
//   - No prompt text is stored — only detection metadata
//   - No PII values stored — only category/rule/severity
//   - No credentials stored
//   - Air-gap compatible — writes locally, no network calls
//
// =========================================================================

package auditlog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/platform"
)

// Entry represents a single detection audit event.
// Only metadata is stored — no prompt text, no PII values, no credentials.
type Entry struct {
	Timestamp     time.Time `json:"timestamp"`
	Direction     string    `json:"direction"`
	Host          string    `json:"host"`
	Path          string    `json:"path,omitempty"`
	TotalDets     int       `json:"total_detections"`
	Blocked       bool      `json:"blocked"`
	PIICategories []string  `json:"pii_categories,omitempty"`
	SecretTypes   []string  `json:"secret_types,omitempty"`
	MLScore       float64   `json:"ml_score,omitempty"`
	Categories    []string  `json:"categories,omitempty"`
	Severities    []string  `json:"severities,omitempty"`
	Rules         []string  `json:"rules,omitempty"`
}

// Logger writes detection audit events to a JSONL file.
type Logger struct {
	mu      sync.Mutex
	file    *os.File
	path    string
	maxSize int64 // bytes
	writer  io.Writer

	// For testing
	nowFunc func() time.Time
}

// DefaultMaxSize is the default maximum log file size before rotation (10 MB).
const DefaultMaxSize = 10 * 1024 * 1024

// New creates a new audit logger writing to the data directory.
func New() (*Logger, error) {
	dir := platform.DataDir()
	return NewWithPath(filepath.Join(dir, "audit.log"), DefaultMaxSize)
}

// NewWithPath creates a logger writing to a specific path.
func NewWithPath(path string, maxSize int64) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create audit log dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	return &Logger{
		file:    f,
		path:    path,
		maxSize: maxSize,
		writer:  f,
		nowFunc: time.Now,
	}, nil
}

// Log writes a detection event to the audit log.
// Only metadata is stored — the original text is never written.
func (l *Logger) Log(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check rotation
	if l.file != nil {
		if info, err := l.file.Stat(); err == nil && info.Size() > l.maxSize {
			if err := l.rotate(); err != nil {
				// Log rotation failed, but don't block the detection
				// Just continue writing to the current file
				_ = err
			}
		}
	}

	e.Timestamp = l.nowFunc()

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	line = append(line, '\n')

	if _, err := l.writer.Write(line); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}

	// Flush to disk for durability
	if f, ok := l.writer.(*os.File); ok {
		_ = f.Sync()
	}

	return nil
}

// Close closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// rotate moves the current log to a timestamped backup and opens a new file.
func (l *Logger) rotate() error {
	if l.file != nil {
		_ = l.file.Close()
	}

	rotated := l.path + "." + l.nowFunc().Format("20060102-150405")
	if err := os.Rename(l.path, rotated); err != nil {
		// If rename fails (e.g., cross-device), try copy+delete
		if err := copyFile(l.path, rotated); err != nil {
			return fmt.Errorf("rotate audit log: %w", err)
		}
		_ = os.Truncate(l.path, 0)
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("reopen audit log after rotate: %w", err)
	}

	l.file = f
	l.writer = f
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
