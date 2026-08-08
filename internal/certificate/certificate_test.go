package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewManager(t *testing.T) {
	mgr := NewManager()
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	if !mgr.IsAutoGenerateEnabled() {
		t.Error("AutoGenerate should be enabled by default")
	}
}

func TestGenerateSelfSigned(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned() /* #nosec */
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}
	if cert == nil {
		t.Fatal("Certificate should not be nil")
	}
	if cert.Certificate == nil {
		t.Fatal("Certificate.Certificate should not be nil")
	}
	if cert.CertBytes == nil {
		t.Fatal("Certificate.CertBytes should not be nil")
	}
	if cert.KeyBytes == nil {
		t.Fatal("Certificate.KeyBytes should not be nil")
	}
	if cert.PrivateKey == nil {
		t.Fatal("Certificate.PrivateKey should not be nil")
	}
	if !cert.Certificate.IsCA {
		t.Error("CA certificate should have IsCA=true")
	}
}

func TestGenerateProxyCertificate(t *testing.T) {
	mgr := NewManager()
	_, err := mgr.GenerateSelfSigned() /* #nosec */
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	proxyCert, err := mgr.GenerateProxyCertificate("api.openai.com") /* #nosec */
	if err != nil {
		t.Fatalf("GenerateProxyCertificate failed: %v", err)
	}
	if proxyCert == nil {
		t.Fatal("Proxy certificate should not be nil")
	}
	if proxyCert.Certificate == nil {
		t.Fatal("Proxy Certificate.Certificate should not be nil")
	}
}

func TestGenerateProxyCertificateMultipleHosts(t *testing.T) {
	mgr := NewManager()
	_, err := mgr.GenerateSelfSigned() /* #nosec */
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	hosts := []string{"api.openai.com", "chat.openai.com", "chatgpt.com"}
	for _, host := range hosts {
		cert, err := mgr.GenerateProxyCertificate(host)
		if err != nil {
			t.Errorf("GenerateProxyCertificate(%s) failed: %v", host, err)
			continue
		}
		if cert == nil {
			t.Errorf("Certificate for %s should not be nil", host)
		}
	}
}

func TestCertificateCache(t *testing.T) {
	mgr := NewManager()
	caCert, _ := mgr.GenerateSelfSigned()                     /* #nosec */
	cert, _ := mgr.GenerateProxyCertificate("api.openai.com") /* #nosec */

	err := mgr.CacheCertificate("api.openai.com", cert)
	if err != nil {
		t.Fatalf("CacheCertificate failed: %v", err)
	}

	cached, err := mgr.GetCertificate("api.openai.com")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cached == nil {
		t.Fatal("Cached certificate should not be nil")
	}
	_ = caCert // suppress unused warning
}

func TestGetCACertificate(t *testing.T) {
	mgr := NewManager()
	_, err := mgr.GenerateSelfSigned() /* #nosec */
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	ca, err := mgr.GetCACertificate()
	if err != nil {
		t.Fatalf("GetCACertificate failed: %v", err)
	}
	if ca == nil {
		t.Fatal("CA certificate should not be nil")
	}
}

func TestAutoGenerateToggle(t *testing.T) {
	mgr := NewManager()
	if !mgr.IsAutoGenerateEnabled() {
		t.Error("AutoGenerate should be enabled by default")
	}
	mgr.DisableAutoGenerate()
	if mgr.IsAutoGenerateEnabled() {
		t.Error("AutoGenerate should be disabled after DisableAutoGenerate()")
	}
	mgr.EnableAutoGenerate()
	if !mgr.IsAutoGenerateEnabled() {
		t.Error("AutoGenerate should be enabled after EnableAutoGenerate()")
	}
}

func TestClearCache(t *testing.T) {
	mgr := NewManager()
	_, _ = mgr.GenerateSelfSigned()
	_, _ = mgr.GenerateProxyCertificate("api.openai.com")
	_ = mgr.CacheCertificate("api.openai.com", nil) /* #nosec */ // won't cache nil but no panic

	count := mgr.GetCertificateCount()
	_ = count // may be 0 if nil wasn't cached
	mgr.ClearCache()
	if mgr.GetCertificateCount() != 0 {
		t.Errorf("After ClearCache, count = %d, want 0", mgr.GetCertificateCount())
	}
}

func TestSave(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned() /* #nosec */
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := tmpDir + "/ca.crt"
	keyPath := tmpDir + "/ca.key"

	err = mgr.Save(cert, certPath, keyPath)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
}

func TestCertificateStruct(t *testing.T) {
	c := &Certificate{
		Certificate: &x509.Certificate{},
		PrivateKey:  nil,
		CertBytes:   []byte("cert"),
		KeyBytes:    []byte("key"),
	}
	if c.Certificate == nil {
		t.Error("Certificate field should not be nil")
	}
}

func TestEncryptDecryptKey(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	// Encrypt
	encrypted, err := EncryptKey(cert.KeyBytes, "test-passphrase-123")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}

	// Verify it's a PEM block with type ENCRYPTED PRIVATE KEY
	block, _ := pem.Decode(encrypted)
	if block == nil {
		t.Fatal("encrypted data is not a valid PEM block")
	}
	if block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Errorf("expected PEM type 'ENCRYPTED PRIVATE KEY', got %q", block.Type)
	}

	// Decrypt
	decrypted, err := DecryptKey(encrypted, "test-passphrase-123")
	if err != nil {
		t.Fatalf("DecryptKey: %v", err)
	}

	// Verify round-trip
	if string(decrypted) != string(cert.KeyBytes) {
		t.Error("decrypted key does not match original")
	}
}

func TestEncryptDecryptKeyWrongPassphrase(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	encrypted, err := EncryptKey(cert.KeyBytes, "correct-passphrase")
	if err != nil {
		t.Fatalf("EncryptKey: %v", err)
	}

	// Decrypt with wrong passphrase should fail
	_, err = DecryptKey(encrypted, "wrong-passphrase")
	if err == nil {
		t.Error("expected error when decrypting with wrong passphrase")
	}
}

func TestEncryptKeyEmptyPassphrase(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	// Empty passphrase should be rejected (encryption requires a passphrase)
	_, err = EncryptKey(cert.KeyBytes, "")
	if err == nil {
		t.Error("expected error when encrypting with empty passphrase")
	}
}

func TestSaveEncrypted(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	keyPath := filepath.Join(tmpDir, "ca.key")

	err = mgr.SaveEncrypted(cert, certPath, keyPath, "my-secret-passphrase")
	if err != nil {
		t.Fatalf("SaveEncrypted: %v", err)
	}

	// Verify cert file is plaintext PEM
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("ReadFile cert: %v", err)
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Errorf("cert file should be a CERTIFICATE PEM block, got %q", certBlock.Type)
	}

	// Verify key file is encrypted PEM
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil || keyBlock.Type != "ENCRYPTED PRIVATE KEY" {
		t.Errorf("key file should be ENCRYPTED PRIVATE KEY PEM block, got %q", keyBlock.Type)
	}

	// Verify key file permissions (0600 on Unix, may differ on Windows)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("Stat key: %v", err)
		}
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("expected key file permissions 0600, got %o", perm)
		}
	}
}

func TestLoadEncrypted(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	keyPath := filepath.Join(tmpDir, "ca.key")

	// Save encrypted
	err = mgr.SaveEncrypted(cert, certPath, keyPath, "load-test-passphrase")
	if err != nil {
		t.Fatalf("SaveEncrypted: %v", err)
	}

	// Load encrypted
	loaded, err := LoadEncrypted(certPath, keyPath, "load-test-passphrase")
	if err != nil {
		t.Fatalf("LoadEncrypted: %v", err)
	}

	// Verify certificate
	if loaded.Certificate == nil {
		t.Error("loaded certificate is nil")
	}
	if loaded.PrivateKey == nil {
		t.Error("loaded private key is nil")
	}
	if string(loaded.CertBytes) != string(cert.CertBytes) {
		t.Error("loaded cert bytes don't match original")
	}
}

func TestLoadEncryptedWrongPassphrase(t *testing.T) {
	mgr := NewManager()
	cert, err := mgr.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	keyPath := filepath.Join(tmpDir, "ca.key")

	err = mgr.SaveEncrypted(cert, certPath, keyPath, "right-pass")
	if err != nil {
		t.Fatalf("SaveEncrypted: %v", err)
	}

	_, err = LoadEncrypted(certPath, keyPath, "wrong-pass")
	if err == nil {
		t.Error("expected error when loading with wrong passphrase")
	}
}

func TestDecryptKeyInvalidData(t *testing.T) {
	// Too short data
	_, err := DecryptKey([]byte("short"), "pass")
	if err == nil {
		t.Error("expected error for too-short encrypted data")
	}

	// Not a PEM block
	_, err = DecryptKey([]byte("not a pem block"), "pass")
	if err == nil {
		t.Error("expected error for non-PEM data")
	}
}
