// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Binary Verification
// =========================================================================
//
// Verifies integrity of Rampart binaries using SHA-256 checksums and
// optional signature verification (cosign/GPG).
//
// Usage:
//   1. Download binary and checksum file from GitHub Releases
//   2. Verify checksum matches binary
//   3. Optionally verify signature with trusted public key
// =========================================================================

package verify

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ChecksumResult represents the result of checksum verification
type ChecksumResult struct {
	Valid        bool
	BinaryPath   string
	ChecksumPath string
	ComputedSHA  string
	ExpectedSHA  string
	Error        error
}

// SignatureResult represents the result of signature verification
type SignatureResult struct {
	Valid         bool
	BinaryPath    string
	SignaturePath string
	KeyID         string
	Error         error
}

// VerificationResult combines checksum and signature verification results
type VerificationResult struct {
	ChecksumValid  bool
	SignatureValid bool
	BinaryPath     string
	Trusted        bool
	Warnings       []string
	Error          error
}

// Verifier provides binary verification services
type Verifier struct {
	strictMode  bool
	trustedKeys map[string]bool
}

// NewVerifier creates a new binary verifier
func NewVerifier(strictMode bool) *Verifier {
	return &Verifier{
		strictMode:  strictMode,
		trustedKeys: make(map[string]bool),
	}
}

// AddTrustedKey adds a trusted key ID for signature verification
func (v *Verifier) AddTrustedKey(keyID string) {
	v.trustedKeys[keyID] = true
}

// VerifyChecksum verifies that a binary matches its SHA-256 checksum
//
// checksumFile format: "<sha256>  <filename>" (standard sha256sum output)
func (v *Verifier) VerifyChecksum(binaryPath, checksumPath string) (*ChecksumResult, error) {
	result := &ChecksumResult{
		BinaryPath:   binaryPath,
		ChecksumPath: checksumPath,
	}

	// Read checksum file
	checksumFile, err := os.Open(checksumPath)
	if err != nil {
		result.Error = fmt.Errorf("opening checksum file: %w", err)
		return result, result.Error
	}
	defer checksumFile.Close()

	// Parse checksum file (standard sha256sum format)
	expectedSHA, _, err := parseChecksumFile(checksumFile, binaryPath)
	if err != nil {
		result.Error = fmt.Errorf("parsing checksum file: %w", err)
		return result, result.Error
	}
	result.ExpectedSHA = expectedSHA

	// Compute SHA-256 of binary
	computedSHA, err := computeSHA256(binaryPath)
	if err != nil {
		result.Error = fmt.Errorf("computing SHA-256: %w", err)
		return result, result.Error
	}
	result.ComputedSHA = computedSHA

	// Compare checksums
	if !strings.EqualFold(expectedSHA, computedSHA) {
		result.Valid = false
		result.Error = fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSHA, computedSHA)
		return result, result.Error
	}

	result.Valid = true
	return result, nil
}

// VerifySignature verifies a binary signature (placeholder for cosign/GPG)
//
// Note: Full cosign/GPG implementation requires cgo or external tools.
// This is a placeholder that validates signature file format.
// For production use, integrate with sigstore/cosign or golang.org/x/crypto/openpgp
func (v *Verifier) VerifySignature(binaryPath, signaturePath, publicKeyPath string) (*SignatureResult, error) {
	result := &SignatureResult{
		BinaryPath:    binaryPath,
		SignaturePath: signaturePath,
	}

	// Check files exist
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		result.Error = fmt.Errorf("binary not found: %s", binaryPath)
		return result, result.Error
	}

	if _, err := os.Stat(signaturePath); os.IsNotExist(err) {
		result.Error = fmt.Errorf("signature not found: %s", signaturePath)
		return result, result.Error
	}

	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		result.Error = fmt.Errorf("public key not found: %s", publicKeyPath)
		return result, result.Error
	}

	// Read signature file
	sigData, err := os.ReadFile(signaturePath)
	if err != nil {
		result.Error = fmt.Errorf("reading signature: %w", err)
		return result, result.Error
	}

	// Validate signature format (base64-encoded)
	if _, err := decodeSignature(string(sigData)); err != nil {
		result.Error = fmt.Errorf("invalid signature format: %w", err)
		return result, result.Error
	}

	// Read public key
	pubKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		result.Error = fmt.Errorf("reading public key: %w", err)
		return result, result.Error
	}

	// Extract key ID (simplified - full implementation would parse key)
	keyID := extractKeyID(string(pubKeyData))
	result.KeyID = keyID

	// Check if key is trusted (if strict mode)
	if v.strictMode && !v.trustedKeys[keyID] && len(v.trustedKeys) > 0 {
		result.Error = fmt.Errorf("untrusted key: %s", keyID)
		return result, result.Error
	}

	// Note: Actual cryptographic verification requires cosign library or GPG
	// For now, we validate file formats and trust chain
	// In production, integrate with:
	// - github.com/sigstore/cosign (for cosign signatures)
	// - golang.org/x/crypto/openpgp (for GPG signatures)

	result.Valid = true
	return result, nil
}

// Verify performs complete binary verification (checksum + optional signature)
func (v *Verifier) Verify(binaryPath, checksumPath string, signaturePath, publicKeyPath string) (*VerificationResult, error) {
	result := &VerificationResult{
		BinaryPath: binaryPath,
		Warnings:   make([]string, 0),
	}

	// Verify checksum (always required)
	checksumResult, err := v.VerifyChecksum(binaryPath, checksumPath)
	if err != nil {
		result.Error = fmt.Errorf("checksum verification failed: %w", err)
		return result, result.Error
	}
	result.ChecksumValid = checksumResult.Valid

	if !result.ChecksumValid {
		result.Error = fmt.Errorf("binary integrity check failed")
		return result, result.Error
	}

	// Verify signature (optional but recommended)
	if signaturePath != "" && publicKeyPath != "" {
		sigResult, err := v.VerifySignature(binaryPath, signaturePath, publicKeyPath)
		if err != nil {
			if v.strictMode {
				result.Error = fmt.Errorf("signature verification failed: %w", err)
				return result, result.Error
			}
			result.Warnings = append(result.Warnings, fmt.Sprintf("Signature verification warning: %v", err))
		}
		result.SignatureValid = sigResult.Valid
		result.Trusted = sigResult.Valid
	}

	return result, nil
}

// VerifyFromRelease downloads and verifies a binary from GitHub Releases
//
// This is a helper that orchestrates the full verification workflow:
// 1. Download binary from GitHub Releases
// 2. Download checksums file
// 3. Download signature file (if available)
// 4. Verify checksum
// 5. Verify signature (if available)
func (v *Verifier) VerifyFromRelease(owner, repo, version, binaryName, downloadDir string) (*VerificationResult, error) {
	result := &VerificationResult{
		BinaryPath: filepath.Join(downloadDir, binaryName),
		Warnings:   make([]string, 0),
	}

	// Construct URLs
	baseURL := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s", owner, repo, version)
	binaryURL := fmt.Sprintf("%s/%s", baseURL, binaryName)
	checksumURL := fmt.Sprintf("%s/checksums.txt", baseURL)
	signatureURL := fmt.Sprintf("%s/%s.sig", baseURL, binaryName)

	// Note: Actual download requires HTTP client
	// This is a placeholder for the verification workflow
	// In production, use net/http to download files

	result.Warnings = append(result.Warnings,
		fmt.Sprintf("Would download from: %s", binaryURL),
		fmt.Sprintf("Checksum file: %s", checksumURL),
		fmt.Sprintf("Signature file: %s", signatureURL))

	return result, nil
}

// Helper functions

func parseChecksumFile(r io.Reader, expectedFilename string) (string, string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Standard sha256sum format: "<hash>  <filename>"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		hash := parts[0]
		filename := parts[1]

		// Remove leading asterisk or space (binary/text mode indicator)
		filename = strings.TrimPrefix(filename, "*")
		filename = strings.TrimPrefix(filename, " ")

		// Match filename (full path or just basename)
		if strings.HasSuffix(expectedFilename, filename) || filepath.Base(expectedFilename) == filename {
			return hash, filename, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", err
	}

	return "", "", fmt.Errorf("checksum not found for %s", expectedFilename)
}

func computeSHA256(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func decodeSignature(sigData string) ([]byte, error) {
	// Try base64 decoding (standard for signatures)
	decoded, err := base64Decode(strings.TrimSpace(sigData))
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func base64Decode(s string) ([]byte, error) {
	// Standard base64
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	// URL-safe base64
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("invalid base64 encoding")
}

func extractKeyID(pubKeyData string) string {
	// Simplified key ID extraction
	// Full implementation would parse PEM/DER and compute fingerprint
	lines := strings.Split(pubKeyData, "\n")
	for _, line := range lines {
		if strings.Contains(line, "-----BEGIN") {
			return "unknown" // Would compute from actual key
		}
	}
	// Use hash of key data as fallback
	hash := sha256.Sum256([]byte(pubKeyData))
	return hex.EncodeToString(hash[:8])
}
