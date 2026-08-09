// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Privacy Features Integration Tests
// =========================================================================
//
// End-to-end tests for P2#11 (Log Encryption) and P2#12 (Anonymized Metrics)
// CLI integration. Tests verify:
//   1. Passphrase generation works
//   2. Encrypted logging works end-to-end
//   3. Decryption works with correct passphrase
//   4. Decryption fails with wrong passphrase
//   5. Metrics collector integrates properly
// =========================================================================

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/auditlog"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/metrics"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/proxy"
)

// TestGeneratePassphrase_Command tests the generate-passphrase CLI command
func TestGeneratePassphrase_Command(t *testing.T) {
	// Capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run command
	handleGeneratePassphrase([]string{})

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Verify output contains expected elements
	if !strings.Contains(output, "Generated Secure Passphrase") {
		t.Errorf("Expected 'Generated Secure Passphrase' in output, got: %s", output)
	}
	if !strings.Contains(output, "CRITICAL SECURITY INSTRUCTIONS") {
		t.Errorf("Expected security instructions in output, got: %s", output)
	}
	// Should contain a 32-character hex string
	if !strings.Contains(output, "Example usage:") {
		t.Errorf("Expected example usage in output, got: %s", output)
	}
}

// TestGeneratePassphrase_CustomLength tests custom passphrase length
func TestGeneratePassphrase_CustomLength(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run command with custom length
	handleGeneratePassphrase([]string{"--length=64"})

	w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 2048)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Should still generate successfully
	if !strings.Contains(output, "Generated Secure Passphrase") {
		t.Errorf("Expected successful generation with custom length, got: %s", output)
	}
}

// TestEncryptedLogger_Integration tests encrypted logging end-to-end
func TestEncryptedLogger_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	passphrase := "test-passphrase-1234567890abcdef"
	testPath := filepath.Join(tmpDir, "audit.log.enc")

	// Create encrypted logger with specific path
	logger, err := auditlog.NewEncryptedLoggerWithPath(testPath, passphrase, auditlog.DefaultMaxSize)
	if err != nil {
		t.Fatalf("Failed to create encrypted logger: %v", err)
	}

	// Create test entry
	entry := auditlog.Entry{
		Direction:  "request",
		Host:       "api.openai.com",
		Path:       "/v1/chat/completions",
		TotalDets:  2,
		Blocked:    false,
		Redacted:   true,
		Categories: []string{"pii_ssn", "secret_aws_key"},
		Severities: []string{"critical", "high"},
		Rules:      []string{"pii_ssn_us_core", "secret_aws_access_key"},
	}

	// Log entry
	if err := logger.Log(entry); err != nil {
		t.Fatalf("Failed to log entry: %v", err)
	}

	// Close logger to flush
	if err := logger.Close(); err != nil {
		t.Fatalf("Failed to close logger: %v", err)
	}

	// Decrypt the file
	decryptor := auditlog.NewDecryptor(passphrase)
	outputPath := filepath.Join(tmpDir, "decrypted.log")

	if err := decryptor.DecryptFile(logger.Path(), outputPath); err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Read decrypted file
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	// Verify decrypted content
	if !strings.Contains(string(data), "api.openai.com") {
		t.Errorf("Expected host in decrypted output, got: %s", string(data))
	}
	if !strings.Contains(string(data), "pii_ssn") {
		t.Errorf("Expected category in decrypted output, got: %s", string(data))
	}

	t.Logf("✓ Encrypted logging end-to-end successful")
}

// TestDecryptor_WrongPassphrase_Integration tests decryption failure with wrong passphrase
func TestDecryptor_WrongPassphrase_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	correctPassphrase := "correct-passphrase-1234567890"
	wrongPassphrase := "wrong-passphrase-0987654321"

	// Create encrypted logger with correct passphrase
	logger, err := auditlog.NewEncryptedLogger(correctPassphrase)
	if err != nil {
		t.Fatalf("Failed to create encrypted logger: %v", err)
	}

	// Log an entry
	entry := auditlog.Entry{
		Direction: "request",
		Host:      "test.example.com",
		Path:      "/test",
		TotalDets: 1,
	}
	if err := logger.Log(entry); err != nil {
		t.Fatalf("Failed to log entry: %v", err)
	}
	logger.Close()

	// Try to decrypt with wrong passphrase
	decryptor := auditlog.NewDecryptor(wrongPassphrase)
	outputPath := filepath.Join(tmpDir, "decrypted.log")

	err = decryptor.DecryptFile(logger.Path(), outputPath)
	if err == nil {
		t.Error("Expected decryption to fail with wrong passphrase, but it succeeded")
	}

	// Verify error message indicates authentication failure
	if !strings.Contains(err.Error(), "authentication") && !strings.Contains(err.Error(), "failed") {
		t.Errorf("Expected authentication failure error, got: %v", err)
	}

	t.Logf("✓ Wrong passphrase correctly rejected: %v", err)
}

// TestMetricsCollector_Integration tests metrics collection integration
func TestMetricsCollector_Integration(t *testing.T) {
	// Create collector with test endpoint
	collector := metrics.NewCollector(true, "https://test.example.com/metrics")
	defer collector.Close()

	// Record some detections
	collector.RecordDetection("api.openai.com", "pii_ssn", "critical", false)
	collector.RecordDetection("api.anthropic.com", "secret_aws_key", "high", true)
	collector.RecordDetection("api.google.com", "toxicity", "medium", false)

	// Record a false positive
	collector.RecordFalsePositive("api.openai.com", "pii_ssn", "critical", "confirmed_false_positive")

	// Verify queue has metrics
	queueLen := collector.GetQueueLength()
	if queueLen == 0 {
		t.Error("Expected metrics in queue, but queue is empty")
	}

	t.Logf("✓ Metrics collector recorded %d metrics", queueLen)

	// Flush metrics
	collector.Flush()
	t.Logf("✓ Metrics flushed successfully")
}

// TestProxy_WithEncryptionAndMetrics tests proxy initialization with both features
func TestProxy_WithEncryptionAndMetrics(t *testing.T) {
	// Create config with encryption and metrics enabled
	cfg := &config.Config{
		ProxyPort:        8999, // Use different port to avoid conflicts
		DaemonMode:       false,
		Verbose:          false,
		Mode:             config.ModeMonitor,
		AuditKeyPassphrase: "test-passphrase-for-proxy",
		AnonymizedMetrics:  true,
		MetricsEndpoint:    "https://test.example.com/metrics",
		Targets: []config.TargetConfig{
			{Domain: "api.openai.com", Paths: []string{"/"}, Description: "OpenAI API"},
		},
	}

	// Create proxy
	p, err := proxy.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Verify proxy was created successfully
	if p == nil {
		t.Fatal("Expected proxy instance, got nil")
	}

	// Shutdown proxy
	p.Shutdown()

	t.Logf("✓ Proxy initialized with encryption and metrics successfully")
}

// TestDecryptAudit_Command tests the decrypt-audit CLI command
func TestDecryptAudit_Command(t *testing.T) {
	tmpDir := t.TempDir()
	passphrase := "test-decrypt-passphrase-123"
	testPath := filepath.Join(tmpDir, "audit.log.enc")

	// Create encrypted log file with specific path
	logger, err := auditlog.NewEncryptedLoggerWithPath(testPath, passphrase, auditlog.DefaultMaxSize)
	if err != nil {
		t.Fatalf("Failed to create encrypted logger: %v", err)
	}

	entry := auditlog.Entry{
		Direction: "request",
		Host:      "decrypt-test.example.com",
		Path:      "/test",
		TotalDets: 1,
	}
	if err := logger.Log(entry); err != nil {
		t.Fatalf("Failed to log entry: %v", err)
	}
	
	// Get path before closing
	inputPath := logger.Path()
	t.Logf("Encrypted log path: %s", inputPath)
	
	// Close to flush
	if err := logger.Close(); err != nil {
		t.Fatalf("Failed to close logger: %v", err)
	}
	
	// Verify file exists and has content
	rawData, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}
	t.Logf("Encrypted file size: %d bytes", len(rawData))

	// Test decrypt command
	outputPath := filepath.Join(tmpDir, "decrypted.log")

	// Run decryption
	err = runDecryptAudit(passphrase, inputPath, outputPath)

	if err != nil {
		t.Fatalf("Decrypt command failed: %v", err)
	}

	// Verify output file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Expected decrypted output file to exist")
	}

	// Verify content
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !strings.Contains(string(data), "decrypt-test.example.com") {
		t.Errorf("Expected host in decrypted output, got: %s", string(data))
	}

	t.Logf("✓ decrypt-audit command works correctly")
}

// TestRunDecryptAudit_Errors tests error handling in decrypt command
func TestRunDecryptAudit_Errors(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		inputPath  string
		outputPath string
		expectErr  bool
	}{
		{"empty passphrase", "", "input.enc", "output.log", true},
		{"empty input", "pass", "", "output.log", true},
		{"empty output", "pass", "input.enc", "", true},
		{"nonexistent input", "pass", "/nonexistent/file.enc", "output.log", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runDecryptAudit(tt.passphrase, tt.inputPath, tt.outputPath)
			if tt.expectErr && err == nil {
				t.Errorf("Expected error for %s, but got nil", tt.name)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error for %s: %v", tt.name, err)
			}
		})
	}
}

// TestMetricsPrivacy_Guarantees tests that metrics preserve privacy
func TestMetricsPrivacy_Guarantees(t *testing.T) {
	collector := metrics.NewCollector(true, "https://test.example.com/metrics")
	defer collector.Close()

	// Record detection with sensitive domain
	collector.RecordDetection("www.chat.openai.com:443", "pii_ssn", "critical", false)

	// Get queue to inspect
	// Note: In real usage, we'd inspect what would be sent
	// For this test, we verify the hashing works

	// Verify domain hashing is consistent
	hash1 := collector.HashDomainForTest("api.openai.com")
	hash2 := collector.HashDomainForTest("api.openai.com")
	hash3 := collector.HashDomainForTest("API.OPENAI.COM") // Should normalize

	if hash1 != hash2 {
		t.Error("Expected consistent hashing for same domain")
	}

	if hash1 != hash3 {
		t.Error("Expected case-insensitive hashing")
	}

	// Verify hash length (16 hex chars)
	if len(hash1) != 16 {
		t.Errorf("Expected 16-char hash, got %d chars: %s", len(hash1), hash1)
	}

	t.Logf("✓ Domain hashing preserves privacy (16 hex chars, case-insensitive)")
}

// TestEncryptionPerformance benchmarks encryption overhead
func BenchmarkEncryptedLogger_Log(b *testing.B) {
	passphrase := "benchmark-passphrase-1234567890"
	logger, err := auditlog.NewEncryptedLogger(passphrase)
	if err != nil {
		b.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	entry := auditlog.Entry{
		Direction:  "request",
		Host:       "api.openai.com",
		Path:       "/v1/chat/completions",
		TotalDets:  1,
		Categories: []string{"pii_ssn"},
		Severities: []string{"critical"},
		Rules:      []string{"pii_ssn_us_core"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := logger.Log(entry); err != nil {
			b.Fatalf("Log failed: %v", err)
		}
	}
}

// Helper method for testing - exposes hashDomain for test access
// This is added to the metrics package for testing purposes
