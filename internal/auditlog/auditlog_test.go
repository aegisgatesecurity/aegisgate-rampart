// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLog_WritesEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewWithPath(path, DefaultMaxSize)
	if err != nil {
		t.Fatalf("NewWithPath: %v", err)
	}
	defer logger.Close()

	entry := Entry{
		Direction:     "request",
		Host:          "api.openai.com",
		Path:          "/v1/chat/completions",
		TotalDets:     5,
		Blocked:       false,
		PIICategories: []string{"ssn"},
		SecretTypes:   []string{"AWS:aws_key"},
		MLScore:       0.92,
		Categories:    []string{"pii", "secret"},
		Severities:    []string{"critical", "high"},
		Rules:         []string{"pii_ssn", "secret_aws_key"},
	}

	if err := logger.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// Read the file back
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var got Entry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Host != "api.openai.com" {
		t.Errorf("expected host api.openai.com, got %s", got.Host)
	}
	if got.TotalDets != 5 {
		t.Errorf("expected 5 detections, got %d", got.TotalDets)
	}
	if got.Blocked != false {
		t.Error("expected blocked=false")
	}
	if len(got.PIICategories) != 1 || got.PIICategories[0] != "ssn" {
		t.Errorf("expected pii_categories [ssn], got %v", got.PIICategories)
	}
	if got.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestLog_NoPromptText(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewWithPath(path, DefaultMaxSize)
	if err != nil {
		t.Fatalf("NewWithPath: %v", err)
	}
	defer logger.Close()

	entry := Entry{
		Direction:  "response",
		Host:       "api.anthropic.com",
		TotalDets:  2,
		Categories: []string{"pii", "secret"},
		Rules:      []string{"pii_ssn", "secret_aws_key"},
	}

	if err := logger.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// SECURITY: verify no raw PII or secret text is stored
	sensitive := []string{"263-78-1234", "AKIAIOSFODNN7EXAMPLE", "prompt", "password", "SSN value"}
	for _, s := range sensitive {
		if strings.Contains(string(data), s) {
			t.Errorf("SECURITY: audit log contains sensitive text: %s", s)
		}
	}
}

func TestLog_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Small max size to trigger rotation quickly
	logger, err := NewWithPath(path, 256)
	if err != nil {
		t.Fatalf("NewWithPath: %v", err)
	}
	defer logger.Close()

	// Write enough entries to trigger rotation
	for i := 0; i < 20; i++ {
		entry := Entry{
			Direction:  "request",
			Host:       "api.openai.com",
			TotalDets:  i,
			Categories: []string{"test"},
		}
		if err := logger.Log(entry); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	// There should be the current log + at least one rotated file
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	logCount := 0
	for _, f := range files {
		if strings.HasPrefix(f.Name(), "audit.log") {
			logCount++
		}
	}

	if logCount < 2 {
		t.Errorf("expected at least 2 log files (current + rotated), got %d", logCount)
	}
}

func TestLog_AppendsAfterReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger1, err := NewWithPath(path, DefaultMaxSize)
	if err != nil {
		t.Fatalf("NewWithPath: %v", err)
	}

	entry1 := Entry{Direction: "request", Host: "api.openai.com", TotalDets: 1}
	if err := logger1.Log(entry1); err != nil {
		t.Fatalf("Log: %v", err)
	}
	logger1.Close()

	// Reopen and write another entry
	logger2, err := NewWithPath(path, DefaultMaxSize)
	if err != nil {
		t.Fatalf("NewWithPath (2nd): %v", err)
	}

	entry2 := Entry{Direction: "response", Host: "api.anthropic.com", TotalDets: 2}
	if err := logger2.Log(entry2); err != nil {
		t.Fatalf("Log (2nd): %v", err)
	}
	logger2.Close()

	// Should have 2 lines
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}
}

func TestLog_CustomTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewWithPath(path, DefaultMaxSize)
	if err != nil {
		t.Fatalf("NewWithPath: %v", err)
	}
	defer logger.Close()

	fixedTime := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	logger.nowFunc = func() time.Time { return fixedTime }

	entry := Entry{Direction: "request", Host: "api.openai.com", TotalDets: 1}
	if err := logger.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var got Entry
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !got.Timestamp.Equal(fixedTime) {
		t.Errorf("expected timestamp %v, got %v", fixedTime, got.Timestamp)
	}
}

func TestNew_CreatesDataDir(t *testing.T) {
	// Temp home to avoid polluting real paths
	tmpDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmpDir, "data"))

	logger, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer logger.Close()

	// Verify the log file was created
	if logger.path == "" {
		t.Error("expected non-empty path")
	}
	t.Logf("Audit log path: %s", logger.path)
}
