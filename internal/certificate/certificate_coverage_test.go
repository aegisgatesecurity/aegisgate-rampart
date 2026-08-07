// SPDX-License-Identifier: Apache-2.0
package certificate

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGenerateProxyCertificate_WithCACert tests GenerateProxyCertificate after CA is already generated.
// Note: GenerateProxyCertificate calls GenerateSelfSigned internally if CA is nil,
// but both acquire mu.Lock, causing a deadlock. So we must generate CA first.
func TestGenerateProxyCertificate_WithCACert(t *testing.T) {
	mgr := NewManager()

	// Generate CA first to avoid deadlock in GenerateProxyCertificate
	_, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	cert, err := mgr.GenerateProxyCertificate("test.example.com")
	if err != nil {
		t.Fatalf("GenerateProxyCertificate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("Certificate should not be nil")
	}

	if cert.Certificate == nil {
		t.Error("Certificate.Certificate should not be nil")
	}

	if cert.Certificate.Subject.CommonName != "test.example.com" {
		t.Errorf("CommonName = %s, want test.example.com", cert.Certificate.Subject.CommonName)
	}
}

// TestGenerateProxyCertificate_Caching tests that GenerateProxyCertificate caches certificates.
func TestGenerateProxyCertificate_Caching(t *testing.T) {
	mgr := NewManager()

	_, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	cert1, err := mgr.GenerateProxyCertificate("cached.example.com")
	if err != nil {
		t.Fatalf("First GenerateProxyCertificate failed: %v", err)
	}

	cert2, err := mgr.GenerateProxyCertificate("cached.example.com")
	if err != nil {
		t.Fatalf("Second GenerateProxyCertificate failed: %v", err)
	}

	if cert1 != cert2 {
		t.Error("GenerateProxyCertificate should return cached certificate for same hostname")
	}
}

// TestGenerateProxyCertificate_DifferentHostnames tests certificates for different hostnames.
func TestGenerateProxyCertificate_DifferentHostnames(t *testing.T) {
	mgr := NewManager()

	_, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	cert1, err := mgr.GenerateProxyCertificate("host1.example.com")
	if err != nil {
		t.Fatalf("GenerateProxyCertificate for host1 failed: %v", err)
	}

	cert2, err := mgr.GenerateProxyCertificate("host2.example.com")
	if err != nil {
		t.Fatalf("GenerateProxyCertificate for host2 failed: %v", err)
	}

	if cert1 == cert2 {
		t.Error("Certificates for different hostnames should be different")
	}

	if cert1.Certificate.Subject.CommonName == cert2.Certificate.Subject.CommonName {
		t.Error("Different hostnames should have different CommonNames")
	}
}

// TestSave_ErrorPaths tests Save with invalid paths.
func TestSave_ErrorPaths(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	// Test saving to a non-existent deep directory
	err = mgr.Save(cert, "/nonexistent/path/cert.pem", "/nonexistent/path/key.pem")
	if err == nil {
		t.Error("Save to nonexistent directory should fail")
	}
}

// TestSave_Success tests Save with valid paths.
func TestSave_Success(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")

	err = mgr.Save(cert, certPath, keyPath)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("Certificate file should exist: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("Key file should exist: %v", err)
	}

	// Verify file contents are valid PEM
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}
	if len(certData) == 0 {
		t.Error("Certificate file should not be empty")
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}
	if len(keyData) == 0 {
		t.Error("Key file should not be empty")
	}
}

// TestGetCACertificate_NotGenerated tests GetCACertificate before generating.
func TestGetCACertificate_NotGenerated(t *testing.T) {
	mgr := NewManager()

	_, err := mgr.GetCACertificate()
	if err == nil {
		t.Error("GetCACertificate should fail when CA cert not generated")
	}
}

// TestGetCertificate_NotCached tests GetCertificate for a non-cached hostname.
func TestGetCertificate_NotCached(t *testing.T) {
	mgr := NewManager()

	_, err := mgr.GetCertificate("nonexistent.example.com")
	if err == nil {
		t.Error("GetCertificate should fail for non-cached hostname")
	}
}

// TestCacheCertificate tests CacheCertificate and GetCertificate.
func TestCacheCertificate_Manual(t *testing.T) {
	mgr := NewManager()
	ca, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	// Cache a certificate manually
	err = mgr.CacheCertificate("manual.example.com", ca)
	if err != nil {
		t.Fatalf("CacheCertificate failed: %v", err)
	}

	// Retrieve it
	retrieved, err := mgr.GetCertificate("manual.example.com")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if retrieved != ca {
		t.Error("Retrieved certificate should be the same object as cached")
	}
}

// TestGetCertificateCount tests GetCertificateCount.
func TestGetCertificateCount(t *testing.T) {
	mgr := NewManager()

	if count := mgr.GetCertificateCount(); count != 0 {
		t.Errorf("Initial count should be 0, got %d", count)
	}

	_, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	if count := mgr.GetCertificateCount(); count != 1 {
		t.Errorf("After generating CA, count should be 1, got %d", count)
	}

	_, err = mgr.GenerateProxyCertificate("test1.example.com")
	if err != nil {
		t.Fatalf("GenerateProxyCertificate failed: %v", err)
	}

	if count := mgr.GetCertificateCount(); count != 2 {
		t.Errorf("After generating proxy cert, count should be 2, got %d", count)
	}
}

// TestClearCache_AfterGeneration tests clearing cache after generating certificates.
func TestClearCache_AfterGeneration(t *testing.T) {
	mgr := NewManager()

	_, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	_, err = mgr.GenerateProxyCertificate("test.example.com")
	if err != nil {
		t.Fatalf("GenerateProxyCertificate failed: %v", err)
	}

	if count := mgr.GetCertificateCount(); count == 0 {
		t.Error("Should have cached certificates before clear")
	}

	mgr.ClearCache()

	if count := mgr.GetCertificateCount(); count != 0 {
		t.Errorf("After ClearCache, count should be 0, got %d", count)
	}
}

// TestAutoGenerateToggle_EnableDisable tests enabling and disabling auto-generation.
func TestAutoGenerateToggle_EnableDisable(t *testing.T) {
	mgr := NewManager()

	if !mgr.IsAutoGenerateEnabled() {
		t.Error("AutoGenerate should be enabled by default")
	}

	mgr.DisableAutoGenerate()
	if mgr.IsAutoGenerateEnabled() {
		t.Error("AutoGenerate should be disabled after DisableAutoGenerate")
	}

	mgr.EnableAutoGenerate()
	if !mgr.IsAutoGenerateEnabled() {
		t.Error("AutoGenerate should be enabled after EnableAutoGenerate")
	}
}

// TestCertificate_CertAndKeyBytes tests that CertBytes and KeyBytes are valid PEM.
func TestCertificate_CertAndKeyBytes(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	if len(cert.CertBytes) == 0 {
		t.Error("CertBytes should not be empty")
	}
	if len(cert.KeyBytes) == 0 {
		t.Error("KeyBytes should not be empty")
	}

	// Verify PEM blocks
	if string(cert.CertBytes[:len("-----BEGIN CERTIFICATE")]) != "-----BEGIN CERTIFICATE" {
		t.Errorf("CertBytes should start with PEM header, got %s", string(cert.CertBytes[:30]))
	}
	if string(cert.KeyBytes[:len("-----BEGIN EC PRIVATE KEY")]) != "-----BEGIN EC PRIVATE KEY" {
		t.Errorf("KeyBytes should start with PEM header, got %s", string(cert.KeyBytes[:30]))
	}
}

// TestCertificate_IsCA tests that the self-signed cert is a CA.
func TestCertificate_IsCA(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	if !cert.Certificate.IsCA {
		t.Error("Self-signed certificate should be a CA")
	}
}

// TestCertificate_ProxyCertNotCA tests that proxy certificates are not CAs.
func TestCertificate_ProxyCertNotCA(t *testing.T) {
	mgr := NewManager()

	_, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	cert, err := mgr.GenerateProxyCertificate("test.example.com")
	if err != nil {
		t.Fatalf("GenerateProxyCertificate failed: %v", err)
	}

	if cert.Certificate.IsCA {
		t.Error("Proxy certificate should NOT be a CA")
	}
}

// TestCertificate_SANs tests that proxy certificates have SANs.
func TestCertificate_SANs(t *testing.T) {
	mgr := NewManager()

	_, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	cert, err := mgr.GenerateProxyCertificate("api.openai.com")
	if err != nil {
		t.Fatalf("GenerateProxyCertificate failed: %v", err)
	}

	foundSAN := false
	for _, name := range cert.Certificate.DNSNames {
		if name == "api.openai.com" {
			foundSAN = true
			break
		}
	}
	if !foundSAN {
		t.Errorf("Proxy certificate should have 'api.openai.com' in SANs, got %v", cert.Certificate.DNSNames)
	}
}

// TestCertificate_ECDSA tests that certificates use ECDSA.
func TestCertificate_ECDSA(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	// Verify private key is ECDSA
	if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Error("Private key should be ECDSA")
	}
}

// TestCertificate_Expiry tests that certificates have reasonable expiry dates.
func TestCertificate_Expiry(t *testing.T) {
	mgr := NewManager()

	// CA cert should expire in ~10 years
	caCert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	caDuration := caCert.Certificate.NotAfter.Sub(caCert.Certificate.NotBefore)
	if caDuration < 9*365*24*time.Hour {
		t.Errorf("CA cert duration should be ~10 years, got %v", caDuration)
	}

	// Proxy cert should expire in ~1 year
	proxyCert, err := mgr.GenerateProxyCertificate("test.example.com")
	if err != nil {
		t.Fatalf("GenerateProxyCertificate failed: %v", err)
	}

	proxyDuration := proxyCert.Certificate.NotAfter.Sub(proxyCert.Certificate.NotBefore)
	if proxyDuration < 360*24*time.Hour {
		t.Errorf("Proxy cert duration should be ~1 year, got %v", proxyDuration)
	}
}
