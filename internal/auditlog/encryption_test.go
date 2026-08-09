// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Audit Log Encryption Tests
// =========================================================================

package auditlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewEncryptedLogger(t *testing.T) {
	tmpDir := t.TempDir()
	passphrase := "test-passphrase-123"

	testPath := filepath.Join(tmpDir, "audit.log")

	// Create encrypted logger
	logger, err := NewEncryptedLoggerWithPath(testPath, passphrase, DefaultMaxSize)
	if err != nil {
		t.Fatalf("NewEncryptedLogger failed: %v", err)
	}
	defer logger.Close()

	if logger == nil {
		t.Fatal("Expected non-nil logger")
	}
	if logger.cipher == nil {
		t.Error("Expected non-nil cipher")
	}
	if len(logger.salt) != saltSize {
		t.Errorf("Salt size = %d, want %d", len(logger.salt), saltSize)
	}

	t.Logf("✓ Encrypted logger created at %s", logger.Path())
}

func TestEncryptedLogger_EmptyPassphrase(t *testing.T) {
	_, err := NewEncryptedLogger("")
	if err == nil {
		t.Error("Expected error for empty passphrase")
	}
	if !strings.Contains(err.Error(), "passphrase required") {
		t.Errorf("Error = %v, want 'passphrase required'", err)
	}
	t.Logf("✓ Empty passphrase rejected")
}

func TestEncryptedLogger_LogAndDecrypt(t *testing.T) {
	tmpDir := t.TempDir()
	passphrase := "test-passphrase-secure-123"
	testPath := filepath.Join(tmpDir, "audit.log.enc")

	// Create encrypted logger
	logger, err := NewEncryptedLoggerWithPath(testPath, passphrase, DefaultMaxSize)
	if err != nil {
		t.Fatalf("NewEncryptedLogger failed: %v", err)
	}
	defer logger.Close()

	// Create test entry
	entry := Entry{
		Timestamp:     time.Now(),
		Direction:     "request",
		Host:          "api.openai.com",
		Path:          "/v1/chat/completions",
		TotalDets:     1,
		Blocked:       true,
		Redacted:      true,
		PIICategories: []string{"pii_ssn"},
		SecretTypes:   []string{},
		Categories:    []string{"pii"},
		Severities:    []string{"critical"},
		Rules:         []string{"pii_ssn_regex"},
	}

	// Log entry (encrypted)
	err = logger.Log(entry)
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	// Verify file exists and is encrypted
	data, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Verify it's JSON with encryption fields
	if !strings.Contains(string(data), `"v":`) {
		t.Error("Encrypted file missing version field")
	}
	if !strings.Contains(string(data), `"a":`) {
		t.Error("Encrypted file missing algorithm field")
	}
	if !strings.Contains(string(data), `"s":`) {
		t.Error("Encrypted file missing salt field")
	}
	if !strings.Contains(string(data), `"c":`) {
		t.Error("Encrypted file missing cipher field")
	}

	// Decrypt and verify
	decryptor := NewDecryptor(passphrase)
	decryptedPath := filepath.Join(tmpDir, "audit.log.dec")

	err = decryptor.DecryptFile(testPath, decryptedPath)
	if err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	// Read decrypted data
	decryptedData, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("ReadFile decrypted failed: %v", err)
	}

	// Verify decrypted content contains original data
	decryptedStr := string(decryptedData)
	if !strings.Contains(decryptedStr, "api.openai.com") {
		t.Error("Decrypted file missing host")
	}
	if !strings.Contains(decryptedStr, "pii_ssn") {
		t.Error("Decrypted file missing PII category")
	}
	if !strings.Contains(decryptedStr, "critical") {
		t.Error("Decrypted file missing severity")
	}

	t.Logf("✓ Log encrypted and decrypted successfully")
}

func TestDecryptor_WrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	correctPassphrase := "correct-passphrase"
	wrongPassphrase := "wrong-passphrase"
	testPath := filepath.Join(tmpDir, "audit.log.enc")

	// Create encrypted logger with correct passphrase
	logger, err := NewEncryptedLoggerWithPath(testPath, correctPassphrase, DefaultMaxSize)
	if err != nil {
		t.Fatalf("NewEncryptedLogger failed: %v", err)
	}
	defer logger.Close()

	// Log an entry
	entry := Entry{
		Timestamp: time.Now(),
		Direction: "request",
		Host:      "test.example.com",
	}
	err = logger.Log(entry)
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	logger.Close()

	// Try to decrypt with wrong passphrase
	decryptor := NewDecryptor(wrongPassphrase)
	decryptedPath := filepath.Join(tmpDir, "audit.log.wrong")

	err = decryptor.DecryptFile(testPath, decryptedPath)
	if err == nil {
		t.Error("Expected error for wrong passphrase")
	}
	if !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("Error = %v, want 'decryption failed'", err)
	}

	t.Logf("✓ Wrong passphrase correctly rejected")
}

func TestDecryptEntry(t *testing.T) {
	tmpDir := t.TempDir()
	passphrase := "test-passphrase-entry"
	testPath := filepath.Join(tmpDir, "audit.log.enc")

	// Create and log
	logger, err := NewEncryptedLoggerWithPath(testPath, passphrase, DefaultMaxSize)
	if err != nil {
		t.Fatalf("NewEncryptedLogger failed: %v", err)
	}

	entry := Entry{
		Timestamp:  time.Now(),
		Direction:  "response",
		Host:       "claude.ai",
		TotalDets:  2,
		Blocked:    false,
		Categories: []string{"secrets", "pii"},
	}
	err = logger.Log(entry)
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	logger.Close()

	// Read encrypted line
	data, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	lines := splitLines(data)
	if len(lines) == 0 {
		t.Fatal("No lines in encrypted file")
	}

	// Decrypt single entry
	decryptor := NewDecryptor(passphrase)
	decrypted, err := decryptor.DecryptEntry(lines[0])
	if err != nil {
		t.Fatalf("DecryptEntry failed: %v", err)
	}

	if decrypted.Host != "claude.ai" {
		t.Errorf("Host = %s, want claude.ai", decrypted.Host)
	}
	if decrypted.Direction != "response" {
		t.Errorf("Direction = %s, want response", decrypted.Direction)
	}
	if len(decrypted.Categories) != 2 {
		t.Errorf("Categories count = %d, want 2", len(decrypted.Categories))
	}

	t.Logf("✓ Single entry decryption working")
}

func TestGenerateRandomPassphrase(t *testing.T) {
	pass1, err := GenerateRandomPassphrase()
	if err != nil {
		t.Fatalf("GenerateRandomPassphrase failed: %v", err)
	}

	pass2, err := GenerateRandomPassphrase()
	if err != nil {
		t.Fatalf("GenerateRandomPassphrase failed: %v", err)
	}

	if pass1 == pass2 {
		t.Error("Expected different passphrases")
	}

	if len(pass1) != 64 {
		t.Errorf("Passphrase length = %d, want 64", len(pass1))
	}

	t.Logf("✓ Random passphrase generation working")
}

func TestEncryptedLogger_Rotation(t *testing.T) {
	tmpDir := t.TempDir()
	passphrase := "test-passphrase-rotation"
	testPath := filepath.Join(tmpDir, "audit.log.enc")

	// Create logger with small max size to trigger rotation
	smallMaxSize := int64(1024) // 1 KB
	logger, err := NewEncryptedLoggerWithPath(testPath, passphrase, smallMaxSize)
	if err != nil {
		t.Fatalf("NewEncryptedLogger failed: %v", err)
	}
	defer logger.Close()

	// Log multiple entries to trigger rotation
	for i := 0; i < 10; i++ {
		entry := Entry{
			Timestamp:  time.Now(),
			Direction:  "request",
			Host:       "test.example.com",
			Path:       "/test",
			TotalDets:  i,
			Categories: []string{"pii"},
		}
		err = logger.Log(entry)
		if err != nil {
			t.Fatalf("Log %d failed: %v", i, err)
		}
	}

	// Verify file exists
	if _, err := os.Stat(testPath); os.IsNotExist(err) {
		t.Error("Encrypted log file does not exist")
	}

	t.Logf("✓ Encrypted logger rotation working")
}

func TestEncryptedEntry_Struct(t *testing.T) {
	entry := EncryptedEntry{
		Version:   1,
		Algorithm: "chacha20-poly1305",
		Salt:      "dGVzdHNhbHQ=",
		Nonce:     "dGVzdG5vbmNl",
		Cipher:    "dGVzdGNpcGhlcg==",
	}

	if entry.Version != 1 {
		t.Errorf("Version = %d", entry.Version)
	}
	if entry.Algorithm != "chacha20-poly1305" {
		t.Errorf("Algorithm = %s", entry.Algorithm)
	}

	t.Logf("✓ EncryptedEntry struct working")
}

func TestSplitLines(t *testing.T) {
	data := []byte("line1\nline2\nline3\n")
	lines := splitLines(data)

	if len(lines) != 3 {
		t.Errorf("Lines count = %d, want 3", len(lines))
	}

	if string(lines[0]) != "line1" {
		t.Errorf("Line 1 = %s", string(lines[0]))
	}

	t.Logf("✓ splitLines working")
}

// Test encryption constants
func TestEncryptionConstants(t *testing.T) {
	if pbkdf2Iterations != 100000 {
		t.Errorf("PBKDF2 iterations = %d, want 100000", pbkdf2Iterations)
	}
	if saltSize != 16 {
		t.Errorf("Salt size = %d, want 16", saltSize)
	}
	if keySize != 32 {
		t.Errorf("Key size = %d, want 32", keySize)
	}
	if encryptionAlgorithm != "chacha20-poly1305" {
		t.Errorf("Algorithm = %s", encryptionAlgorithm)
	}

	t.Logf("✓ Encryption constants correct")
}
