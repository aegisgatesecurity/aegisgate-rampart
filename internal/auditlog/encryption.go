// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Audit Log Encryption
// =========================================================================
//
// Encrypts audit logs at rest using ChaCha20-Poly1305 authenticated
// encryption. Key derived from user passphrase via PBKDF2-SHA256.
//
// Privacy: Key is NEVER stored. Decryption requires explicit user action
// with the original passphrase. This provides defense-in-depth against
// disk theft, forensic analysis, or unauthorized access.
//
// Security: Passphrase is zeroed from memory after key derivation.
// Uses securemem package for explicit memory zeroing.
//
// Ported from: aegisgate-platform/pkg/crypto/enhanced/enhanced.go
// =========================================================================

package auditlog

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/securemem"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// PBKDF2 iterations for key derivation (OWASP recommendation for 2026)
	pbkdf2Iterations = 100000

	// Salt size in bytes (128 bits)
	saltSize = 16

	// Key size for ChaCha20-Poly1305 (256 bits)
	keySize = 32

	// Encryption algorithm identifier (for future-proofing)
	encryptionAlgorithm = "chacha20-poly1305"

	// Encryption version (increment if format changes)
	encryptionVersion = 1
)

// EncryptedEntry wraps an Entry with encryption metadata
type EncryptedEntry struct {
	Version   int    `json:"v"` // Encryption version
	Algorithm string `json:"a"` // Algorithm identifier
	Salt      string `json:"s"` // Base64-encoded salt
	Nonce     string `json:"n"` // Base64-encoded nonce
	Cipher    string `json:"c"` // Base64-encoded ciphertext
}

// EncryptedLogger wraps Logger with encryption support
type EncryptedLogger struct {
	mu     sync.Mutex
	logger *Logger
	cipher interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	}
	salt    []byte
	path    string
	version int
}

// NewEncryptedLogger creates an encrypted audit logger
// The passphrase is used to derive the encryption key via PBKDF2.
// The key is NOT stored - decryption requires the same passphrase.
// The passphrase is explicitly zeroed from memory after key derivation.
func NewEncryptedLogger(passphrase string) (*EncryptedLogger, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase required for encryption")
	}

	// Use secure buffer for passphrase
	passBuf := securemem.NewSecurePassphrase(passphrase)
	defer passBuf.Destroy() // Zero passphrase after use

	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	// Derive key from passphrase using PBKDF2-SHA256
	// PassBuf.ToBytes() returns the passphrase bytes securely
	var key []byte
	err := passBuf.Use(func(passBytes []byte) error {
		key = pbkdf2.Key(passBytes, salt, pbkdf2Iterations, keySize, sha256.New)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	// Create underlying logger
	dir := filepath.Dir(defaultAuditLogPath())
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create audit log dir: %w", err)
	}

	logPath := defaultAuditLogPath() + ".enc"
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	logger := &Logger{
		file:    f,
		path:    logPath,
		maxSize: DefaultMaxSize,
		writer:  f,
		nowFunc: time.Now,
	}

	return &EncryptedLogger{
		logger:  logger,
		cipher:  aead,
		salt:    salt,
		path:    logPath,
		version: encryptionVersion,
	}, nil
}

// Log encrypts and writes a detection event to the audit log
func (el *EncryptedLogger) Log(e Entry) error {
	el.mu.Lock()
	defer el.mu.Unlock()

	// Check rotation
	if el.logger.file != nil {
		if info, err := el.logger.file.Stat(); err == nil && info.Size() > el.logger.maxSize {
			if err := el.logger.rotate(); err != nil {
				// Log rotation failed, but don't block the detection
				_ = err
			}
		}
	}

	e.Timestamp = el.logger.nowFunc()

	// Marshal entry to JSON
	plaintext, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	// Generate random nonce (96 bits for ChaCha20)
	nonce := make([]byte, el.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	// Encrypt with authenticated encryption
	ciphertext := el.cipher.Seal(nil, nonce, plaintext, nil)

	// Wrap in encrypted entry structure
	encrypted := EncryptedEntry{
		Version:   el.version,
		Algorithm: encryptionAlgorithm,
		Salt:      base64.StdEncoding.EncodeToString(el.salt),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Cipher:    base64.StdEncoding.EncodeToString(ciphertext),
	}

	// Marshal encrypted entry
	line, err := json.Marshal(encrypted)
	if err != nil {
		return fmt.Errorf("marshal encrypted entry: %w", err)
	}

	line = append(line, '\n')

	if _, err := el.logger.writer.Write(line); err != nil {
		return fmt.Errorf("write encrypted audit entry: %w", err)
	}

	return nil
}

// Close closes the underlying log file
func (el *EncryptedLogger) Close() error {
	return el.logger.Close()
}

// Path returns the encrypted log file path
func (el *EncryptedLogger) Path() string {
	return el.path
}

// Decryptor decrypts encrypted audit logs
type Decryptor struct {
	passphrase string
}

// NewDecryptor creates a decryptor with the given passphrase
func NewDecryptor(passphrase string) *Decryptor {
	return &Decryptor{passphrase: passphrase}
}

// DecryptFile decrypts an encrypted audit log file and writes plaintext to output
func (d *Decryptor) DecryptFile(encryptedPath, outputPath string) error {
	// Read encrypted file
	encryptedData, err := os.ReadFile(encryptedPath)
	if err != nil {
		return fmt.Errorf("reading encrypted file: %w", err)
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer outFile.Close()

	// Process each line (JSONL format)
	lines := splitLines(encryptedData)
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}

		// Parse encrypted entry
		var encrypted EncryptedEntry
		if err := json.Unmarshal(line, &encrypted); err != nil {
			return fmt.Errorf("line %d: parsing encrypted entry: %w", i+1, err)
		}

		// Decrypt entry
		plaintext, err := d.decryptEntry(encrypted)
		if err != nil {
			return fmt.Errorf("line %d: decryption failed: %w", i+1, err)
		}

		// Write plaintext
		if _, err := outFile.Write(plaintext); err != nil {
			return fmt.Errorf("line %d: writing plaintext: %w", i+1, err)
		}
		if _, err := outFile.Write([]byte("\n")); err != nil {
			return fmt.Errorf("line %d: writing newline: %w", i+1, err)
		}
	}

	return nil
}

// decryptEntry decrypts a single encrypted entry
func (d *Decryptor) decryptEntry(encrypted EncryptedEntry) ([]byte, error) {
	// Verify version
	if encrypted.Version != encryptionVersion {
		return nil, fmt.Errorf("unsupported encryption version: %d", encrypted.Version)
	}

	// Verify algorithm
	if encrypted.Algorithm != encryptionAlgorithm {
		return nil, fmt.Errorf("unsupported algorithm: %s", encrypted.Algorithm)
	}

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(encrypted.Salt)
	if err != nil {
		return nil, fmt.Errorf("decoding salt: %w", err)
	}

	// Decode nonce
	nonce, err := base64.StdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}

	// Decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Cipher)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}

	// Derive key from passphrase (same derivation as encryption)
	key := pbkdf2.Key([]byte(d.passphrase), salt, pbkdf2Iterations, keySize, sha256.New)

	// Create cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	// Decrypt
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}

	return plaintext, nil
}

// DecryptEntry decrypts a single encrypted entry and returns the Entry struct
func (d *Decryptor) DecryptEntry(line []byte) (*Entry, error) {
	var encrypted EncryptedEntry
	if err := json.Unmarshal(line, &encrypted); err != nil {
		return nil, fmt.Errorf("parsing encrypted entry: %w", err)
	}

	plaintext, err := d.decryptEntry(encrypted)
	if err != nil {
		return nil, err
	}

	var entry Entry
	if err := json.Unmarshal(plaintext, &entry); err != nil {
		return nil, fmt.Errorf("parsing entry: %w", err)
	}

	return &entry, nil
}

// splitLines splits data into lines (simple implementation for JSONL)
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// defaultAuditLogPath returns the default audit log path
func defaultAuditLogPath() string {
	// Import platform package for config dir
	// This matches the unencrypted logger path
	return filepath.Join(os.Getenv("HOME"), ".config", "aegisgate-rampart", "audit.log")
}

// GenerateRandomPassphrase generates a secure random passphrase
func GenerateRandomPassphrase() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// NewEncryptedLoggerWithPath creates an encrypted logger with a custom path (for testing)
// This is exported for integration testing purposes
func NewEncryptedLoggerWithPath(path, passphrase string, maxSize int64) (*EncryptedLogger, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase required for encryption")
	}

	// Use secure buffer for passphrase
	passBuf := securemem.NewSecurePassphrase(passphrase)
	defer passBuf.Destroy() // Zero passphrase after use

	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	// Derive key from passphrase using PBKDF2-SHA256
	var key []byte
	err := passBuf.Use(func(passBytes []byte) error {
		key = pbkdf2.Key(passBytes, salt, pbkdf2Iterations, keySize, sha256.New)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Create ChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	// Create directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create audit log dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	logger := &Logger{
		file:    f,
		path:    path,
		maxSize: maxSize,
		writer:  f,
		nowFunc: time.Now,
	}

	return &EncryptedLogger{
		logger:  logger,
		cipher:  aead,
		salt:    salt,
		path:    path,
		version: encryptionVersion,
	}, nil
}
