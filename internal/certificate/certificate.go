// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/upstream/aegisgate/pkg/certificate (v4.0.0)
// =========================================================================
// =========================================================================
//
// =========================================================================

package certificate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// HIGH-4: maximum cert cache size (LRU eviction when exceeded)
const maxCertCacheSize = 1000

// Certificate represents a certificate with its key
type Certificate struct {
	Certificate *x509.Certificate
	PrivateKey  interface{}
	CertBytes   []byte
	KeyBytes    []byte
}

// Manager handles certificate generation and management
type Manager struct {
	mu            sync.RWMutex
	certCache     map[string]*Certificate
	autoGenerate  bool
	caCertificate *Certificate
	caPrivateKey  interface{}
}

// NewManager creates a new certificate manager
func NewManager() *Manager {
	return &Manager{
		certCache:    make(map[string]*Certificate),
		autoGenerate: true,
	}
}

// GenerateSelfSigned generates a self-signed CA certificate
func (m *Manager) GenerateSelfSigned() (*Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// MEDIUM-1 FIX: use cryptographically random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "AegisGate CA",
			Organization: []string{"AegisGate"},
			Country:      []string{"US"},
			Province:     []string{"California"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// HIGH-6 FIX: restrict CA to only sign end-entity certs, not subordinate CAs
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certObj := &Certificate{
		Certificate: cert,
		PrivateKey:  key,
		CertBytes:   certPEM,
		KeyBytes:    keyPEM,
	}
	m.certCache["self-signed-ca"] = certObj
	m.caCertificate = certObj
	m.caPrivateKey = key

	return certObj, nil
}

// GenerateProxyCertificate generates a proxy certificate for MITM
func (m *Manager) GenerateProxyCertificate(hostname string) (*Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.caCertificate == nil {
		ca, err := m.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		m.caCertificate = ca
	}

	if cached, exists := m.certCache[hostname]; exists {
		return cached, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// MEDIUM-1 FIX: use cryptographically random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"AegisGate"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// LOW-1 FIX: use IP SAN for IP addresses, DNS SAN for hostnames
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, m.caCertificate.Certificate, &key.PublicKey, m.caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certObj := &Certificate{
		Certificate: cert,
		PrivateKey:  key,
		CertBytes:   certPEM,
		KeyBytes:    keyPEM,
	}
	m.certCache[hostname] = certObj

	// HIGH-4 FIX: evict oldest entries when cache exceeds max size
	if len(m.certCache) > maxCertCacheSize {
		// Simple eviction: remove one random entry (not truly LRU, but bounded)
		for k := range m.certCache {
			if k != "self-signed-ca" && k != hostname {
				delete(m.certCache, k)
				break
			}
		}
	}

	return certObj, nil
}

// LoadCAFromFiles loads a CA certificate and private key from PEM files.
// CRITICAL-2 FIX: allows the file-based CA (installed by user) to be used
// for signing MITM certificates, instead of generating a separate CA.
func (m *Manager) LoadCAFromFiles(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}

	parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	var privateKey interface{}
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return fmt.Errorf("unsupported CA key type %q", keyBlock.Type)
	}
	if err != nil {
		return fmt.Errorf("parse CA private key: %w", err)
	}

	certObj := &Certificate{
		Certificate: parsedCert,
		PrivateKey:  privateKey,
		CertBytes:   certPEM,
		KeyBytes:    keyPEM,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certCache["self-signed-ca"] = certObj
	m.caCertificate = certObj
	m.caPrivateKey = privateKey

	return nil
}

// Save saves a certificate to file
func (m *Manager) Save(cert *Certificate, certPath, keyPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.WriteFile(certPath, cert.CertBytes, 0600); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, cert.KeyBytes, 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	return nil
}

// GetCACertificate returns the CA certificate
func (m *Manager) GetCACertificate() (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.caCertificate == nil {
		return nil, fmt.Errorf("CA certificate not generated yet")
	}
	return m.caCertificate, nil
}

// CacheCertificate caches a certificate
func (m *Manager) CacheCertificate(hostname string, cert *Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certCache[hostname] = cert
	return nil
}

// GetCertificate retrieves a cached certificate
func (m *Manager) GetCertificate(hostname string) (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, exists := m.certCache[hostname]
	if !exists {
		return nil, fmt.Errorf("certificate not found for %s", hostname)
	}
	return cert, nil
}

// EnableAutoGenerate enables automatic certificate generation
func (m *Manager) EnableAutoGenerate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.autoGenerate = true
}

// DisableAutoGenerate disables automatic certificate generation
func (m *Manager) DisableAutoGenerate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.autoGenerate = false
}

// IsAutoGenerateEnabled checks if auto-generation is enabled
func (m *Manager) IsAutoGenerateEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.autoGenerate
}

// GetCertificateCount returns the number of cached certificates
func (m *Manager) GetCertificateCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.certCache)
}

// ClearCache clears all cached certificates
func (m *Manager) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certCache = make(map[string]*Certificate)
}

// EncryptKey encrypts PEM-encoded key bytes using a passphrase-derived AES-256-GCM key.
// The encrypted output is a PEM block of type "ENCRYPTED PRIVATE KEY" containing:
// salt (32 bytes) + nonce (12 bytes) + ciphertext + GCM authentication tag.
// A random 32-byte salt is generated for each encryption call.
// The passphrase is NOT stored — if lost, the key cannot be recovered.
func EncryptKey(keyPEM []byte, passphrase string) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}

	// Generate random salt (32 bytes) and nonce (12 bytes)
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Derive a 32-byte AES key using HKDF-SHA256
	pseudorandomKey := hkdf.Extract(sha256.New, []byte(passphrase), salt)
	aesKeyReader := hkdf.Expand(sha256.New, pseudorandomKey, []byte("aegisgate-rampart-ca-key"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(aesKeyReader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// ciphertext includes the GCM auth tag appended
	ciphertext := aead.Seal(nil, nonce, keyPEM, nil)

	// Combine: salt (32) + nonce (12) + ciphertext + tag
	combined := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	combined = append(combined, salt...)
	combined = append(combined, nonce...)
	combined = append(combined, ciphertext...)

	// Encode as PEM block
	pemBlock := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: combined,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// DecryptKey decrypts an "ENCRYPTED PRIVATE KEY" PEM block using a passphrase.
// It reverses EncryptKey: extracts salt and nonce, re-derives the AES key,
// and decrypts to recover the original PEM-encoded key bytes.
func DecryptKey(encryptedPEM []byte, passphrase string) ([]byte, error) {
	block, _ := pem.Decode(encryptedPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("expected PEM type 'ENCRYPTED PRIVATE KEY', got %q", block.Type)
	}

	data := block.Bytes
	if len(data) < 32+12+1 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract salt (32 bytes), nonce (12 bytes), and ciphertext+tag
	salt := data[:32]
	nonce := data[32:44]
	ciphertext := data[44:]

	// Derive the same AES key using HKDF-SHA256
	pseudorandomKey := hkdf.Extract(sha256.New, []byte(passphrase), salt)
	aesKeyReader := hkdf.Expand(sha256.New, pseudorandomKey, []byte("aegisgate-rampart-ca-key"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(aesKeyReader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Decrypt with AES-256-GCM
	block2, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block2)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: wrong passphrase or corrupted data")
	}

	return plaintext, nil
}

// SaveEncrypted works like Save but encrypts the private key with a passphrase
// before writing to disk. The certificate (.crt/.pem) is NOT encrypted (it's public).
// File permissions for the encrypted key are still 0600.
func (m *Manager) SaveEncrypted(cert *Certificate, certPath, keyPath string, passphrase string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Write the certificate as-is (public, not encrypted)
	if err := os.WriteFile(certPath, cert.CertBytes, 0600); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Encrypt and write the private key
	encryptedKey, err := EncryptKey(cert.KeyBytes, passphrase)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}
	if err := os.WriteFile(keyPath, encryptedKey, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted key: %w", err)
	}

	return nil
}

// LoadEncrypted loads an encrypted key file given a passphrase, returning a usable
// TLS certificate. The certificate file (.crt) is read as plaintext; the key
// file is decrypted using the passphrase.
func LoadEncrypted(certPath, keyPath string, passphrase string) (*Certificate, error) {
	// Read the certificate (public, not encrypted)
	certPEM, err := os.ReadFile(certPath) // #nosec G304 -- cert path from config
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode certificate PEM block")
	}

	parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Read and decrypt the private key
	encryptedKeyPEM, err := os.ReadFile(keyPath) // #nosec G304 -- key path from config
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted key: %w", err)
	}

	keyPEM, err := DecryptKey(encryptedKeyPEM, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Parse the decrypted key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode decrypted key PEM block")
	}

	var privateKey interface{}
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyBlock.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &Certificate{
		Certificate: parsedCert,
		PrivateKey:  privateKey,
		CertBytes:   certPEM,
		KeyBytes:    keyPEM,
	}, nil
}
