// SPDX-License-Identifier: Apache-2.0
// Test coverage for LoadCAFromFiles in internal/certificate

package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadCAFromFiles(t *testing.T) {
	// Generate a test CA cert and key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	keyPath := filepath.Join(tmpDir, "ca.key")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0644); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// Test successful load
	m := NewManager()
	err = m.LoadCAFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCAFromFiles failed: %v", err)
	}

	ca, caErr := m.GetCACertificate()
	if caErr != nil {
		t.Errorf("GetCACertificate returned error: %v", caErr)
	}
	if ca == nil {
		t.Error("GetCACertificate returned nil after LoadCAFromFiles")
	}
	if !ca.Certificate.IsCA {
		t.Error("Loaded CA cert should have IsCA=true")
	}

	// Test non-existent cert file
	err = m.LoadCAFromFiles("/nonexistent/cert.pem", keyPath)
	if err == nil {
		t.Error("LoadCAFromFiles should fail for non-existent cert file")
	}

	// Test non-existent key file
	err = m.LoadCAFromFiles(certPath, "/nonexistent/key.pem")
	if err == nil {
		t.Error("LoadCAFromFiles should fail for non-existent key file")
	}

	// Test invalid cert PEM
	badCertPath := filepath.Join(tmpDir, "bad.crt")
	if err := os.WriteFile(badCertPath, []byte("not a PEM file"), 0644); err != nil {
		t.Fatalf("write bad cert: %v", err)
	}
	err = m.LoadCAFromFiles(badCertPath, keyPath)
	if err == nil {
		t.Error("LoadCAFromFiles should fail for invalid cert PEM")
	}

	// Test invalid key PEM
	badKeyPath := filepath.Join(tmpDir, "bad.key")
	if err := os.WriteFile(badKeyPath, []byte("not a PEM file"), 0644); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	err = m.LoadCAFromFiles(certPath, badKeyPath)
	if err == nil {
		t.Error("LoadCAFromFiles should fail for invalid key PEM")
	}

	// Test unsupported key type
	fakeKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "UNKNOWN KEY", Bytes: []byte("fake")})
	fakeKeyPath := filepath.Join(tmpDir, "fake.key")
	if err := os.WriteFile(fakeKeyPath, fakeKeyPEM, 0644); err != nil {
		t.Fatalf("write fake key: %v", err)
	}
	err = m.LoadCAFromFiles(certPath, fakeKeyPath)
	if err == nil {
		t.Error("LoadCAFromFiles should fail for unsupported key type")
	}
}
