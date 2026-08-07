package certificate

import (
	"crypto/x509"
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
	mgr.GenerateSelfSigned()                        /* #nosec */
	mgr.GenerateProxyCertificate("api.openai.com")  /* #nosec */
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
