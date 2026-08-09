// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Binary Verification Tests
// =========================================================================

package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewVerifier(t *testing.T) {
	v := NewVerifier(false)
	if v == nil {
		t.Fatal("Expected verifier instance, got nil")
	}
	if v.strictMode {
		t.Error("Expected strictMode to be false")
	}
	if len(v.trustedKeys) != 0 {
		t.Error("Expected no trusted keys")
	}

	vStrict := NewVerifier(true)
	if !vStrict.strictMode {
		t.Error("Expected strictMode to be true")
	}
}

func TestAddTrustedKey(t *testing.T) {
	v := NewVerifier(false)
	v.AddTrustedKey("key1")
	v.AddTrustedKey("key2")

	if !v.trustedKeys["key1"] {
		t.Error("Expected key1 to be trusted")
	}
	if !v.trustedKeys["key2"] {
		t.Error("Expected key2 to be trusted")
	}
	if len(v.trustedKeys) != 2 {
		t.Errorf("Expected 2 trusted keys, got %d", len(v.trustedKeys))
	}
}

func TestVerifyChecksum_Valid(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test binary
	binaryPath := filepath.Join(tmpDir, "test-binary")
	testData := []byte("test binary content")
	if err := os.WriteFile(binaryPath, testData, 0755); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Compute checksum
	hash := sha256.Sum256(testData)
	checksum := hex.EncodeToString(hash[:])

	// Create checksum file (standard sha256sum format)
	checksumPath := filepath.Join(tmpDir, "checksums.txt")
	checksumContent := checksum + "  test-binary\n"
	if err := os.WriteFile(checksumPath, []byte(checksumContent), 0644); err != nil {
		t.Fatalf("Failed to create checksum file: %v", err)
	}

	// Verify
	v := NewVerifier(false)
	result, err := v.VerifyChecksum(binaryPath, checksumPath)

	if err != nil {
		t.Fatalf("VerifyChecksum failed: %v", err)
	}
	if !result.Valid {
		t.Error("Expected checksum to be valid")
	}
	if result.ComputedSHA != checksum {
		t.Errorf("Computed SHA mismatch: expected %s, got %s", checksum, result.ComputedSHA)
	}
	if result.ExpectedSHA != checksum {
		t.Errorf("Expected SHA mismatch: expected %s, got %s", checksum, result.ExpectedSHA)
	}
}

func TestVerifyChecksum_Invalid(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test binary
	binaryPath := filepath.Join(tmpDir, "test-binary")
	if err := os.WriteFile(binaryPath, []byte("test content"), 0755); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	// Create checksum file with wrong checksum
	checksumPath := filepath.Join(tmpDir, "checksums.txt")
	wrongChecksum := "0000000000000000000000000000000000000000000000000000000000000000"
	checksumContent := wrongChecksum + "  test-binary\n"
	if err := os.WriteFile(checksumPath, []byte(checksumContent), 0644); err != nil {
		t.Fatalf("Failed to create checksum file: %v", err)
	}

	// Verify
	v := NewVerifier(false)
	result, err := v.VerifyChecksum(binaryPath, checksumPath)

	if err == nil {
		t.Fatal("Expected error for invalid checksum")
	}
	if result.Valid {
		t.Error("Expected checksum to be invalid")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("Expected checksum mismatch error, got: %v", err)
	}
}

func TestVerifyChecksum_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	binaryPath := filepath.Join(tmpDir, "nonexistent")
	checksumPath := filepath.Join(tmpDir, "checksums.txt")

	v := NewVerifier(false)
	_, err := v.VerifyChecksum(binaryPath, checksumPath)

	if err == nil {
		t.Fatal("Expected error for missing file")
	}
}

func TestVerifySignature_Valid(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	binaryPath := filepath.Join(tmpDir, "test-binary")
	signaturePath := filepath.Join(tmpDir, "test.sig")
	publicKeyPath := filepath.Join(tmpDir, "test.pub")

	testData := []byte("test binary")
	signature := base64.StdEncoding.EncodeToString([]byte("fake-signature"))
	publicKey := "-----BEGIN PUBLIC KEY-----\nfake-key-data\n-----END PUBLIC KEY-----"

	if err := os.WriteFile(binaryPath, testData, 0755); err != nil {
		t.Fatalf("Failed to create binary: %v", err)
	}
	if err := os.WriteFile(signaturePath, []byte(signature), 0644); err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}
	if err := os.WriteFile(publicKeyPath, []byte(publicKey), 0644); err != nil {
		t.Fatalf("Failed to create public key: %v", err)
	}

	// Verify
	v := NewVerifier(false)
	result, err := v.VerifySignature(binaryPath, signaturePath, publicKeyPath)

	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !result.Valid {
		t.Error("Expected signature to be valid")
	}
	if result.KeyID == "" {
		t.Error("Expected key ID to be set")
	}
}

func TestVerifySignature_MissingFiles(t *testing.T) {
	tmpDir := t.TempDir()

	binaryPath := filepath.Join(tmpDir, "test-binary")
	signaturePath := filepath.Join(tmpDir, "test.sig")
	publicKeyPath := filepath.Join(tmpDir, "test.pub")

	// Create only binary
	if err := os.WriteFile(binaryPath, []byte("test"), 0755); err != nil {
		t.Fatalf("Failed to create binary: %v", err)
	}

	v := NewVerifier(false)

	// Test missing signature
	_, err := v.VerifySignature(binaryPath, signaturePath, publicKeyPath)
	if err == nil {
		t.Error("Expected error for missing signature file")
	}

	// Create signature, test missing key
	if err := os.WriteFile(signaturePath, []byte("sig"), 0644); err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}
	_, err = v.VerifySignature(binaryPath, signaturePath, publicKeyPath)
	if err == nil {
		t.Error("Expected error for missing public key file")
	}
}

func TestVerifySignature_InvalidFormat(t *testing.T) {
	tmpDir := t.TempDir()

	binaryPath := filepath.Join(tmpDir, "test-binary")
	signaturePath := filepath.Join(tmpDir, "test.sig")
	publicKeyPath := filepath.Join(tmpDir, "test.pub")

	if err := os.WriteFile(binaryPath, []byte("test"), 0755); err != nil {
		t.Fatalf("Failed to create binary: %v", err)
	}
	// Invalid base64 signature
	if err := os.WriteFile(signaturePath, []byte("not-valid-base64!!!"), 0644); err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}
	if err := os.WriteFile(publicKeyPath, []byte("key"), 0644); err != nil {
		t.Fatalf("Failed to create public key: %v", err)
	}

	v := NewVerifier(false)
	_, err := v.VerifySignature(binaryPath, signaturePath, publicKeyPath)

	if err == nil {
		t.Error("Expected error for invalid signature format")
	}
	if !strings.Contains(err.Error(), "invalid signature format") {
		t.Errorf("Expected invalid format error, got: %v", err)
	}
}

func TestVerifySignature_StrictMode_Untrusted(t *testing.T) {
	tmpDir := t.TempDir()

	binaryPath := filepath.Join(tmpDir, "test-binary")
	signaturePath := filepath.Join(tmpDir, "test.sig")
	publicKeyPath := filepath.Join(tmpDir, "test.pub")

	testData := []byte("test")
	signature := base64.StdEncoding.EncodeToString([]byte("sig"))
	publicKey := "-----BEGIN PUBLIC KEY-----\ndata-----END PUBLIC KEY-----"

	if err := os.WriteFile(binaryPath, testData, 0755); err != nil {
		t.Fatalf("Failed to create binary: %v", err)
	}
	if err := os.WriteFile(signaturePath, []byte(signature), 0644); err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}
	if err := os.WriteFile(publicKeyPath, []byte(publicKey), 0644); err != nil {
		t.Fatalf("Failed to create public key: %v", err)
	}

	// Strict mode with trusted key (different from test key)
	v := NewVerifier(true)
	v.AddTrustedKey("trusted-key-123")

	_, err := v.VerifySignature(binaryPath, signaturePath, publicKeyPath)

	if err == nil {
		t.Error("Expected error for untrusted key in strict mode")
	}
	if !strings.Contains(err.Error(), "untrusted") {
		t.Errorf("Expected untrusted key error, got: %v", err)
	}
}

func TestVerify_Complete(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test binary
	binaryPath := filepath.Join(tmpDir, "test-binary")
	testData := []byte("test binary content")
	if err := os.WriteFile(binaryPath, testData, 0755); err != nil {
		t.Fatalf("Failed to create binary: %v", err)
	}

	// Compute and write checksum
	hash := sha256.Sum256(testData)
	checksum := hex.EncodeToString(hash[:])
	checksumPath := filepath.Join(tmpDir, "checksums.txt")
	if err := os.WriteFile(checksumPath, []byte(checksum+"  test-binary\n"), 0644); err != nil {
		t.Fatalf("Failed to create checksum file: %v", err)
	}

	// Create signature and key
	signaturePath := filepath.Join(tmpDir, "test.sig")
	publicKeyPath := filepath.Join(tmpDir, "test.pub")
	signature := base64.StdEncoding.EncodeToString([]byte("valid-sig"))
	publicKey := "-----BEGIN PUBLIC KEY-----\ndata-----END PUBLIC KEY-----"
	if err := os.WriteFile(signaturePath, []byte(signature), 0644); err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}
	if err := os.WriteFile(publicKeyPath, []byte(publicKey), 0644); err != nil {
		t.Fatalf("Failed to create public key: %v", err)
	}

	// Verify complete
	v := NewVerifier(false)
	result, err := v.Verify(binaryPath, checksumPath, signaturePath, publicKeyPath)

	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !result.ChecksumValid {
		t.Error("Expected checksum to be valid")
	}
	if !result.SignatureValid {
		t.Error("Expected signature to be valid")
	}
	if len(result.Warnings) != 0 {
		t.Errorf("Expected no warnings, got: %v", result.Warnings)
	}
}

func TestVerify_ChecksumFails(t *testing.T) {
	tmpDir := t.TempDir()

	binaryPath := filepath.Join(tmpDir, "test-binary")
	if err := os.WriteFile(binaryPath, []byte("test"), 0755); err != nil {
		t.Fatalf("Failed to create binary: %v", err)
	}

	checksumPath := filepath.Join(tmpDir, "checksums.txt")
	wrongChecksum := "0000000000000000000000000000000000000000000000000000000000000000"
	if err := os.WriteFile(checksumPath, []byte(wrongChecksum+"  test-binary\n"), 0644); err != nil {
		t.Fatalf("Failed to create checksum file: %v", err)
	}

	v := NewVerifier(false)
	result, err := v.Verify(binaryPath, checksumPath, "", "")

	if err == nil {
		t.Fatal("Expected error for failed checksum")
	}
	if result.ChecksumValid {
		t.Error("Expected checksum to be invalid")
	}
}

func TestParseChecksumFile(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "standard format",
			content:  "abc123  test-binary\n",
			expected: "abc123",
		},
		{
			name:     "binary mode (asterisk)",
			content:  "abc123 *test-binary\n",
			expected: "abc123",
		},
		{
			name:     "with comments",
			content:  "# comment\nabc123  test-binary\n",
			expected: "abc123",
		},
		{
			name:     "multiple entries",
			content:  "abc123  binary1\ndef456  test-binary\n",
			expected: "def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, filename, err := parseChecksumFile(strings.NewReader(tt.content), "test-binary")
			if err != nil {
				t.Fatalf("parseChecksumFile failed: %v", err)
			}
			if hash != tt.expected {
				t.Errorf("Expected hash %s, got %s", tt.expected, hash)
			}
			if filename != "test-binary" {
				t.Errorf("Expected filename test-binary, got %s", filename)
			}
		})
	}
}

func TestComputeSHA256(t *testing.T) {
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "test")
	testData := []byte("test data")

	if err := os.WriteFile(testPath, testData, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	expectedHash := sha256.Sum256(testData)
	expectedHex := hex.EncodeToString(expectedHash[:])

	hash, err := computeSHA256(testPath)
	if err != nil {
		t.Fatalf("computeSHA256 failed: %v", err)
	}
	if hash != expectedHex {
		t.Errorf("Expected %s, got %s", expectedHex, hash)
	}
}

func TestBase64Decode(t *testing.T) {
	testData := "Hello, World!"
	encoded := base64.StdEncoding.EncodeToString([]byte(testData))

	decoded, err := base64Decode(encoded)
	if err != nil {
		t.Fatalf("base64Decode failed: %v", err)
	}
	if string(decoded) != testData {
		t.Errorf("Expected %s, got %s", testData, string(decoded))
	}

	// Test URL-safe encoding
	encodedURL := base64.URLEncoding.EncodeToString([]byte(testData))
	decodedURL, err := base64Decode(encodedURL)
	if err != nil {
		t.Fatalf("base64Decode URL-safe failed: %v", err)
	}
	if string(decodedURL) != testData {
		t.Errorf("Expected %s, got %s", testData, string(decodedURL))
	}

	// Test invalid
	_, err = base64Decode("invalid!!!")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

func TestExtractKeyID(t *testing.T) {
	// Test with PEM header
	pemKey := "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----"
	keyID := extractKeyID(pemKey)
	if keyID == "" {
		t.Error("Expected key ID to be set")
	}

	// Test with plain data
	plainKey := "some-key-data"
	keyID = extractKeyID(plainKey)
	if len(keyID) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("Expected 16-char key ID, got %d chars", len(keyID))
	}
}
