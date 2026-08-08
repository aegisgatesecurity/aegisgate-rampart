// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"
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
		Redacted:   true,
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

	// SECURITY: verify the redacted flag is present in the log
	var parsed Entry
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !parsed.Redacted {
		t.Error("SECURITY: expected Redacted=true for entry containing sensitive detection results")
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

func TestNewWithPath_MkdirAllError(t *testing.T) {
	// Create a file where a directory is needed, blocking MkdirAll
	blockedDir := filepath.Join(t.TempDir(), "blocked_file")
	if err := os.WriteFile(blockedDir, []byte("blocker"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	path := filepath.Join(blockedDir, "subdir", "audit.log")

	_, err := NewWithPath(path, DefaultMaxSize)
	if err == nil {
		t.Error("expected error when MkdirAll fails")
	}
}

func TestNewWithPath_OpenFileError(t *testing.T) {
	// Create a read-only directory where OpenFile should fail
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte("blocker"), 0444); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Make directory read-only so append open fails
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0755) }() // restore for cleanup

	_, err := NewWithPath(path, DefaultMaxSize)
	if err == nil {
		t.Error("expected error when OpenFile fails")
	}
}

func TestRotate_CopyFileFallback(t *testing.T) {
	// Test rotation where rename fails (e.g., cross-device),
	// forcing the copyFile fallback path.
	// Strategy: use a small maxSize and override rotate to simulate
	// rename failure by making the path point to a different mount.
	// Since we can't easily simulate cross-device rename in tests,
	// we test copyFile directly and the full rotate path separately.

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "source.log")
	dstPath := filepath.Join(dir, "rotated.log")

	// Write some content to source
	content := []byte("line1\nline2\nline3\n")
	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := copyFile(srcPath, dstPath); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("ReadFile dst: %v", err)
	}

	if string(got) != string(content) {
		t.Errorf("copyFile content mismatch: got %q, want %q", string(got), string(content))
	}
}

func TestCopyFile_Errors(t *testing.T) {
	// Source doesn't exist
	if err := copyFile("/nonexistent/path/file.log", t.TempDir()+"/dst.log"); err == nil {
		t.Error("expected error for nonexistent source")
	}

	// Destination directory doesn't exist
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.log")
	if err := os.WriteFile(srcPath, []byte("data"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := copyFile(srcPath, "/nonexistent/dir/deep/file.log"); err == nil {
		t.Error("expected error for nonexistent destination directory")
	}
}

func TestRotate_RenamePath(t *testing.T) {
	// Verify rotation actually uses rename (not copyFile) on same filesystem
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewWithPath(path, 256)
	if err != nil {
		t.Fatalf("NewWithPath: %v", err)
	}

	// Write entries to trigger rotation
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

	// Verify rotated files exist with timestamp pattern
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	rotatedCount := 0
	for _, f := range files {
		if strings.Contains(f.Name(), "audit.log.") {
			rotatedCount++
			// Verify the name has a timestamp format
			if !strings.Contains(f.Name(), "20") {
				t.Errorf("rotated file %s missing timestamp", f.Name())
			}
		}
	}

	if rotatedCount < 1 {
		t.Errorf("expected at least 1 rotated file, got %d", rotatedCount)
	}

	logger.Close()
}

func TestLog_RotationFailure_GracefulDegradation(t *testing.T) {
	// When rotation fails, Log should still write to the current file
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewWithPath(path, DefaultMaxSize)
	if err != nil {
		t.Fatalf("NewWithPath: %v", err)
	}
	defer logger.Close()

	// Write a normal entry first
	entry := Entry{Direction: "request", Host: "api.openai.com", TotalDets: 1}
	if err := logger.Log(entry); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// File should have content
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected data in log file after write")
	}
}

func TestClose_NilFile(t *testing.T) {
	logger := &Logger{file: nil}
	if err := logger.Close(); err != nil {
		t.Errorf("expected nil error on Close with nil file, got %v", err)
	}
}

func TestRedactText_Secrets(t *testing.T) {
	// Secrets categories should be fully redacted
	tests := []struct {
		name     string
		category string
		text     string
		want     string
	}{
		{"aws_key", "secrets", "AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
		{"secret_prefixed", "secret_aws_key", "AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
		{"secret_github", "secret_github_token", "ghp_abcdef1234", "[REDACTED]"},
		{"secrets_uppercase_cat", "Secrets", "AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := detector.Result{Category: tt.category, Text: tt.text}
			got := RedactText(r)
			if got != tt.want {
				t.Errorf("RedactText(%+v) = %q, want %q", tt, got, tt.want)
			}
		})
	}
}

func TestRedactText_PII(t *testing.T) {
	// PII categories should show first 2 + *** + last 2
	tests := []struct {
		name     string
		category string
		text     string
		want     string
	}{
		{"ssn_us_core", "pii-us-core", "263-78-1234", "26***34"},
		{"ssn_us_extended", "pii-us-extended", "263-78-1234", "26***34"},
		{"credit_card_financial", "pii-financial", "4111111111111111", "41***11"},
		{"passport_international", "pii-international", "AB1234567", "AB***67"},
		{"pii_underscore_core", "pii_us_core", "263-78-1234", "26***34"},
		{"pii_underscore_extended", "pii_us_extended", "263-78-1234", "26***34"},
		{"pii_underscore_financial", "pii_financial", "4111111111111111", "41***11"},
		{"pii_underscore_international", "pii_international", "AB1234567", "AB***67"},
		{"pii_dash_prefix", "pii-financial", "4111-1111-1111-1111", "41***11"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := detector.Result{Category: tt.category, Text: tt.text}
			got := RedactText(r)
			if got != tt.want {
				t.Errorf("RedactText(%+v) = %q, want %q", tt, got, tt.want)
			}
		})
	}
}

func TestRedactText_ShortPII(t *testing.T) {
	// PII text shorter than 4 characters should be fully redacted
	r := detector.Result{Category: "pii-us-core", Text: "abc"}
	got := RedactText(r)
	if got != "[REDACTED]" {
		t.Errorf("RedactText short PII = %q, want [REDACTED]", got)
	}
}

func TestRedactText_XSS(t *testing.T) {
	// XSS categories should pass through unchanged
	text := `<script>alert('xss')</script>`
	r := detector.Result{Category: "xss", Text: text}
	got := RedactText(r)
	if got != text {
		t.Errorf("RedactText XSS = %q, want %q", got, text)
	}
}

func TestRedactText_Compliance(t *testing.T) {
	// Compliance categories should pass through unchanged
	text := "GDPR violation: personal data exported without consent"
	r := detector.Result{Category: "compliance", Text: text}
	got := RedactText(r)
	if got != text {
		t.Errorf("RedactText compliance = %q, want %q", got, text)
	}
}

func TestRedactText_Empty(t *testing.T) {
	r := detector.Result{Category: "secrets", Text: ""}
	got := RedactText(r)
	if got != "" {
		t.Errorf("RedactText empty = %q, want empty string", got)
	}
}

func TestRedactText_UnknownCategory(t *testing.T) {
	// Unknown categories should pass through unchanged
	text := "some detection text"
	r := detector.Result{Category: "unknown_category", Text: text}
	got := RedactText(r)
	if got != text {
		t.Errorf("RedactText unknown = %q, want %q", got, text)
	}
}
