// SPDX-License-Identifier: Apache-2.0

package certinit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// createTestCertificate creates a self-signed x509 certificate with the given validity period.
func createTestCertificate(t *testing.T, key crypto.Signer, notBefore, notAfter time.Time, isCA bool) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}

	return cert
}

// writeCertPEM writes a certificate to disk as PEM.
func writeCertPEM(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatalf("failed to write cert PEM: %v", err)
	}
}

// writeKeyPEM writes a private key to disk as PEM (ECDSA format).
func writeKeyPEM(t *testing.T, path string, key crypto.Signer) {
	t.Helper()

	var keyBytes []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatalf("failed to marshal ECDSA key: %v", err)
		}
		keyBytes = b
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(k)
		keyBytes = b
	default:
		t.Fatalf("unsupported key type: %T", key)
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("failed to write key PEM: %v", err)
	}
}

// writePKCS8KeyPEM writes a private key in PKCS8 format to disk.
func writePKCS8KeyPEM(t *testing.T, path string, key interface{}) {
	t.Helper()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8 key: %v", err)
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("failed to write PKCS8 key PEM: %v", err)
	}
}

// writePKCS1RSAKeyPEM writes an RSA private key in PKCS1 format to disk.
func writePKCS1RSAKeyPEM(t *testing.T, path string, key *rsa.PrivateKey) {
	t.Helper()

	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("failed to write PKCS1 RSA key PEM: %v", err)
	}
}

// generateTestCertSet creates a complete set of CA + server certs/keys with the given validity periods.
// Returns the directory path.
func generateTestCertSet(t *testing.T, serverNotBefore, serverNotAfter, caNotBefore, caNotAfter time.Time) string {
	t.Helper()

	dir := t.TempDir()

	// Generate CA key and cert
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caCert := createTestCertificate(t, caKey, caNotBefore, caNotAfter, true)

	// Generate server key and cert
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	serverCert := createTestCertificate(t, serverKey, serverNotBefore, serverNotAfter, false)

	// Write all files
	writeCertPEM(t, filepath.Join(dir, "ca.crt"), caCert)
	writeKeyPEM(t, filepath.Join(dir, "ca.key"), caKey)
	writeCertPEM(t, filepath.Join(dir, "server.crt"), serverCert)
	writeKeyPEM(t, filepath.Join(dir, "server.key"), serverKey)

	return dir
}

// --- checkExistingCerts coverage tests ---

func TestCheckExistingCertsExpiredServerCertReal(t *testing.T) {
	now := time.Now()
	dir := generateTestCertSet(t,
		now.Add(-2*365*24*time.Hour), now.Add(-24*time.Hour), // server cert expired yesterday
		now, now.AddDate(10, 0, 0), // CA cert valid for 10 years
	)

	existing, warnings := checkExistingCerts(
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "ca.key"),
	)
	if existing {
		t.Error("should not return existing with expired server cert")
	}

	foundExpiredWarning := false
	for _, w := range warnings {
		if len(w) > 0 && (contains(w, "expired") || contains(w, "server certificate expired")) {
			foundExpiredWarning = true
		}
	}
	if !foundExpiredWarning {
		t.Errorf("expected expired server cert warning, got: %v", warnings)
	}
}

func TestCheckExistingCertsServerCertExpiresSoon(t *testing.T) {
	now := time.Now()
	// Server cert expires in 15 days (within 30-day threshold)
	dir := generateTestCertSet(t,
		now.Add(-350*24*time.Hour), now.Add(15*24*time.Hour), // server cert expires soon
		now, now.AddDate(10, 0, 0), // CA cert valid for 10 years
	)

	existing, warnings := checkExistingCerts(
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "ca.key"),
	)
	// Should still return existing=true but with a warning
	if !existing {
		t.Error("should return existing=true for server cert that expires soon (but hasn't expired)")
	}

	foundExpiryWarning := false
	for _, w := range warnings {
		if contains(w, "expires soon") {
			foundExpiryWarning = true
		}
	}
	if !foundExpiryWarning {
		t.Errorf("expected 'expires soon' warning for server cert, got: %v", warnings)
	}
}

func TestCheckExistingCertsExpiredCACertReal(t *testing.T) {
	now := time.Now()
	dir := generateTestCertSet(t,
		now, now.AddDate(1, 0, 0), // server cert valid
		now.Add(-2*365*24*time.Hour), now.Add(-24*time.Hour), // CA cert expired yesterday
	)

	existing, warnings := checkExistingCerts(
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "ca.key"),
	)
	if existing {
		t.Error("should not return existing with expired CA cert")
	}

	foundExpiredWarning := false
	for _, w := range warnings {
		if contains(w, "CA certificate expired") {
			foundExpiredWarning = true
		}
	}
	if !foundExpiredWarning {
		t.Errorf("expected expired CA cert warning, got: %v", warnings)
	}
}

func TestCheckExistingCertsCACertExpiresSoon(t *testing.T) {
	now := time.Now()
	// CA cert expires in 60 days (within 90-day threshold)
	dir := generateTestCertSet(t,
		now, now.AddDate(1, 0, 0), // server cert valid for 1 year
		now, now.Add(60*24*time.Hour), // CA cert expires in 60 days
	)

	existing, warnings := checkExistingCerts(
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "ca.key"),
	)
	// Should return existing=true but with a warning about CA cert expiring soon
	if !existing {
		t.Error("should return existing=true for CA cert that expires soon (but hasn't expired)")
	}

	foundExpiryWarning := false
	for _, w := range warnings {
		if contains(w, "CA certificate expires soon") {
			foundExpiryWarning = true
		}
	}
	if !foundExpiryWarning {
		t.Errorf("expected 'CA certificate expires soon' warning, got: %v", warnings)
	}
}

func TestCheckExistingCertsInvalidServerKeyFile(t *testing.T) {
	now := time.Now()
	dir := generateTestCertSet(t,
		now, now.AddDate(1, 0, 0), // server cert valid
		now, now.AddDate(10, 0, 0), // CA cert valid
	)

	// Overwrite server key with invalid data
	serverKeyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(serverKeyPath, []byte("-----BEGIN EC PRIVATE KEY-----\nINVALIDDATA\n-----END EC PRIVATE KEY-----"), 0600); err != nil {
		t.Fatal(err)
	}

	existing, warnings := checkExistingCerts(
		filepath.Join(dir, "server.crt"),
		serverKeyPath,
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "ca.key"),
	)
	if existing {
		t.Error("should not return existing with invalid server key")
	}

	foundKeyWarning := false
	for _, w := range warnings {
		if contains(w, "server key invalid") {
			foundKeyWarning = true
		}
	}
	if !foundKeyWarning {
		t.Errorf("expected 'server key invalid' warning, got: %v", warnings)
	}
}

func TestCheckExistingCertsInvalidCAKeyFile(t *testing.T) {
	now := time.Now()
	dir := generateTestCertSet(t,
		now, now.AddDate(1, 0, 0), // server cert valid
		now, now.AddDate(10, 0, 0), // CA cert valid
	)

	// Overwrite CA key with invalid data
	caKeyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(caKeyPath, []byte("-----BEGIN EC PRIVATE KEY-----\nINVALIDDATA\n-----END EC PRIVATE KEY-----"), 0600); err != nil {
		t.Fatal(err)
	}

	existing, warnings := checkExistingCerts(
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
		filepath.Join(dir, "ca.crt"),
		caKeyPath,
	)
	if existing {
		t.Error("should not return existing with invalid CA key")
	}

	foundKeyWarning := false
	for _, w := range warnings {
		if contains(w, "CA key invalid") {
			foundKeyWarning = true
		}
	}
	if !foundKeyWarning {
		t.Errorf("expected 'CA key invalid' warning, got: %v", warnings)
	}
}

// --- parseCertificateFile coverage tests ---

func TestParseCertificateFileNonCertificatePEMBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notacert.crt")

	// Write a PEM block that is NOT a CERTIFICATE type (e.g., RSA PRIVATE KEY)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("failed to write PEM: %v", err)
	}

	_, err = parseCertificateFile(path)
	if err == nil {
		t.Error("expected error for non-CERTIFICATE PEM block")
	}
	if !contains(err.Error(), "no CERTIFICATE PEM block") {
		t.Errorf("expected 'no CERTIFICATE PEM block' error, got: %v", err)
	}
}

// --- parseKeyFile coverage tests ---

func TestParseKeyFilePKCS8(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkcs8.key")

	// Generate an ECDSA key and write it in PKCS8 format
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	writePKCS8KeyPEM(t, path, ecKey)

	parsedKey, err := parseKeyFile(path)
	if err != nil {
		t.Fatalf("failed to parse PKCS8 key: %v", err)
	}
	if parsedKey == nil {
		t.Error("expected non-nil parsed key")
	}
}

func TestParseKeyFilePKCS8RSA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkcs8-rsa.key")

	// Generate an RSA key and write it in PKCS8 format
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	writePKCS8KeyPEM(t, path, rsaKey)

	parsedKey, err := parseKeyFile(path)
	if err != nil {
		t.Fatalf("failed to parse PKCS8 RSA key: %v", err)
	}
	if parsedKey == nil {
		t.Error("expected non-nil parsed key")
	}
}

func TestParseKeyFilePKCS1RSA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkcs1-rsa.key")

	// Generate an RSA key and write it in PKCS1 format
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	writePKCS1RSAKeyPEM(t, path, rsaKey)

	parsedKey, err := parseKeyFile(path)
	if err != nil {
		t.Fatalf("failed to parse PKCS1 RSA key: %v", err)
	}
	if parsedKey == nil {
		t.Error("expected non-nil parsed key")
	}
}

func TestParseKeyFileNoPEMBlockContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nopem.key")

	// Write raw binary data that is not PEM at all
	if err := os.WriteFile(path, []byte("this is just random text with no pem blocks"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := parseKeyFile(path)
	if err == nil {
		t.Error("expected error for file with no PEM block")
	}
	if !contains(err.Error(), "no PEM block") {
		t.Errorf("expected 'no PEM block' error, got: %v", err)
	}
}

// --- EnsureCerts coverage tests ---

func TestEnsureCertsMkdirFailure(t *testing.T) {
	cfg := Config{
		CertDir:      "/proc/nonexistent/certs", // cannot create dirs under /proc
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	_, err := EnsureCerts(cfg)
	if err == nil {
		t.Error("expected error when mkdir fails")
	}
	if !contains(err.Error(), "failed to create cert directory") {
		t.Errorf("expected mkdir error message, got: %v", err)
	}
}

// --- parseCertificateFile additional coverage ---

func TestParseCertificateFileInvalidDER(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalider.crt")

	// Write a valid CERTIFICATE PEM block but with invalid DER bytes
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("this is not valid DER content")}); err != nil {
		t.Fatalf("failed to write PEM: %v", err)
	}

	_, err = parseCertificateFile(path)
	if err == nil {
		t.Error("expected error for CERTIFICATE PEM block with invalid DER")
	}
	if !contains(err.Error(), "parse failed") {
		t.Errorf("expected 'parse failed' error, got: %v", err)
	}
}

// --- ValidateCerts coverage tests ---

func TestValidateCertsExpiredServerCertReal(t *testing.T) {
	now := time.Now()
	// Create certs where server cert is expired
	dir := generateTestCertSet(t,
		now.Add(-2*365*24*time.Hour), now.Add(-24*time.Hour), // server cert expired yesterday
		now, now.AddDate(10, 0, 0), // CA cert valid
	)

	cfg := Config{
		CertDir:      dir,
		AutoGenerate: false,
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with expired server cert")
	}

	foundExpiryIssue := false
	for _, issue := range v.Issues {
		if contains(issue, "server certificate is EXPIRED") {
			foundExpiryIssue = true
		}
	}
	if !foundExpiryIssue {
		t.Errorf("expected 'server certificate is EXPIRED' issue, got: %v", v.Issues)
	}
}

func TestValidateCertsServerCertExpiresSoon(t *testing.T) {
	now := time.Now()
	// Server cert expires in 15 days (within 30-day threshold)
	dir := generateTestCertSet(t,
		now.Add(-350*24*time.Hour), now.Add(15*24*time.Hour), // server cert expires soon
		now, now.AddDate(10, 0, 0), // CA cert valid
	)

	cfg := Config{
		CertDir:      dir,
		AutoGenerate: false,
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with server cert expiring soon")
	}

	foundExpiryIssue := false
	for _, issue := range v.Issues {
		if contains(issue, "expires within 30 days") {
			foundExpiryIssue = true
		}
	}
	if !foundExpiryIssue {
		t.Errorf("expected 'expires within 30 days' issue, got: %v", v.Issues)
	}
}

func TestValidateCertsExpiredCACertReal(t *testing.T) {
	now := time.Now()
	// Create certs where CA cert is expired
	dir := generateTestCertSet(t,
		now, now.AddDate(1, 0, 0), // server cert valid
		now.Add(-2*365*24*time.Hour), now.Add(-24*time.Hour), // CA cert expired yesterday
	)

	cfg := Config{
		CertDir:      dir,
		AutoGenerate: false,
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	v, err := ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts error: %v", err)
	}
	if v.Valid {
		t.Error("should not be valid with expired CA cert")
	}

	foundExpiryIssue := false
	for _, issue := range v.Issues {
		if contains(issue, "CA certificate is EXPIRED") {
			foundExpiryIssue = true
		}
	}
	if !foundExpiryIssue {
		t.Errorf("expected 'CA certificate is EXPIRED' issue, got: %v", v.Issues)
	}
}

// helper to check if a string contains a substring (case-sensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
