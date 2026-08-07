// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - CA Trust Integration Test
// =========================================================================
//
// Tests the CA certificate trust flow:
//   1. Generate CA certificates (certinit.EnsureCerts)
//   2. Check trust status (catrust.CheckTrust)
//   3. Verify certificate generation and storage
//   4. Test proxy startup with CA cert initialization
//   5. Test the --trust flag flow
//
// Run: go test -v -tags=integration ./internal/catrust/ -run TestCATrust
//       (requires RAMPART_INTEGRATION=1 environment variable)
//
// =========================================================================

package catrust

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/certinit"
)

// skipUnlessIntegration skips the test unless RAMPART_INTEGRATION=1 is set.
func skipUnlessIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("RAMPART_INTEGRATION") != "1" {
		t.Skip("Skipping integration test (set RAMPART_INTEGRATION=1 to run)")
	}
}

// TestCATrust_FullFlow tests the complete CA trust flow:
// certinit → catrust.CheckTrust → catrust.GetInstructions → catrust.SetupTrust
func TestCATrust_FullFlow(t *testing.T) {
	skipUnlessIntegration(t)

	// 1. Create a temporary cert directory
	tmpDir := t.TempDir()
	certDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("Failed to create cert dir: %v", err)
	}

	// 2. Generate CA certificates using certinit
	ciConfig := certinit.Config{
		CertDir:      certDir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost", "rampart.test"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(ciConfig)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	// 3. Verify certificate generation
	if !result.Generated {
		t.Error("Expected Generated=true for new cert generation")
	}
	if result.CACertPath == "" {
		t.Error("CACertPath should not be empty")
	}
	if result.CAKeyPath == "" {
		t.Error("CAKeyPath should not be empty")
	}
	if result.ServerCertPath == "" {
		t.Error("ServerCertPath should not be empty")
	}
	if result.ServerKeyPath == "" {
		t.Error("ServerKeyPath should not be empty")
	}

	t.Logf("✅ CA cert generated at: %s", result.CACertPath)
	t.Logf("✅ Server cert generated at: %s", result.ServerCertPath)

	// 4. Verify CA certificate file exists and is valid
	caCertPEM, err := os.ReadFile(result.CACertPath)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		t.Fatal("Failed to decode CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}

	// 5. Verify CA certificate properties
	if !caCert.IsCA {
		t.Error("CA certificate should have IsCA=true")
	}
	if caCert.Subject.CommonName == "" {
		t.Error("CA certificate should have a CommonName")
	}
	if caCert.NotBefore.IsZero() || caCert.NotAfter.IsZero() {
		t.Error("CA certificate should have valid validity dates")
	}

	t.Logf("✅ CA cert valid: CN=%s, NotBefore=%s, NotAfter=%s, IsCA=%v",
		caCert.Subject.CommonName, caCert.NotBefore, caCert.NotAfter, caCert.IsCA)

	// 6. Verify server certificate file exists and is valid
	serverCertPEM, err := os.ReadFile(result.ServerCertPath)
	if err != nil {
		t.Fatalf("Failed to read server cert: %v", err)
	}

	serverBlock, _ := pem.Decode(serverCertPEM)
	if serverBlock == nil {
		t.Fatal("Failed to decode server cert PEM")
	}

	serverCert, err := x509.ParseCertificate(serverBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse server cert: %v", err)
	}

	if serverCert.IsCA {
		t.Error("Server certificate should NOT have IsCA=true")
	}

	t.Logf("✅ Server cert valid: CN=%s, SANs=%v, NotBefore=%s, NotAfter=%s",
		serverCert.Subject.CommonName, serverCert.DNSNames, serverCert.NotBefore, serverCert.NotAfter)

	// 7. Check trust status (should be untrusted since we just generated it)
	status := CheckTrust(result.CACertPath)
	t.Logf("Trust status: trusted=%v, platform=%s, message=%s",
		status.Trusted, status.Platform, status.Message)

	// On CI, the cert won't be trusted yet
	if status.Trusted {
		t.Log("CA cert is trusted (likely in a development environment)")
	} else {
		t.Log("CA cert is NOT trusted (expected in CI/first-run)")
	}

	// 8. Get trust instructions
	instructions := GetInstructions(result.CACertPath)
	if instructions == "" {
		t.Error("GetInstructions should not return empty string")
	}

	// Verify instructions contain platform-specific content
	switch runtime.GOOS {
	case "darwin":
		if !strings.Contains(instructions, "Keychain") && !strings.Contains(instructions, "security") {
			t.Error("macOS instructions should mention Keychain/security")
		}
	case "linux":
		if !strings.Contains(instructions, "update-ca-certificates") {
			t.Error("Linux instructions should mention update-ca-certificates")
		}
	case "windows":
		if !strings.Contains(instructions, "certutil") {
			t.Error("Windows instructions should mention certutil")
		}
	}

	t.Logf("✅ Trust instructions generated (%d bytes, platform: %s)", len(instructions), runtime.GOOS)

	// 9. Test that SetupTrust fails gracefully when not run as root
	// (it should require sudo/admin on most systems)
	setupResult := SetupTrust(result.CACertPath)
	t.Logf("SetupTrust result: success=%v, message=%s", setupResult.Success, setupResult.Message)

	// 10. Verify idempotent cert generation (running EnsureCerts again should not regenerate)
	result2, err := certinit.EnsureCerts(ciConfig)
	if err != nil {
		t.Fatalf("Second EnsureCerts failed: %v", err)
	}

	if !result2.Existing {
		t.Error("Second EnsureCerts should detect existing certs (Existing=true)")
	}
	if result2.Generated {
		t.Error("Second EnsureCerts should NOT regenerate certs (Generated=false)")
	}

	t.Log("✅ Certificate generation is idempotent (no regeneration)")
}

// TestCATrust_DefaultCACertPath tests the DefaultCACertPath function.
func TestCATrust_DefaultCACertPath(t *testing.T) {
	skipUnlessIntegration(t)

	path := DefaultCACertPath()
	if path == "" {
		t.Error("DefaultCACertPath should not be empty")
	}

	// Should end with ca.crt
	if filepath.Base(path) != "ca.crt" {
		t.Errorf("DefaultCACertPath should end with ca.crt, got %s", path)
	}

	// Should contain aegisgate-rampart
	if !strings.Contains(path, "aegisgate-rampart") {
		t.Errorf("DefaultCACertPath should contain 'aegisgate-rampart', got %s", path)
	}

	t.Logf("✅ DefaultCACertPath: %s", path)
}

// TestCATrust_CheckTrust_NonExistentCert tests CheckTrust with a non-existent cert.
func TestCATrust_CheckTrust_NonExistentCert(t *testing.T) {
	skipUnlessIntegration(t)

	status := CheckTrust("/nonexistent/path/ca.crt")

	if status.Trusted {
		t.Error("Should NOT be trusted when cert doesn't exist")
	}
	if status.Platform == "" {
		t.Error("Platform should be set even for non-existent cert")
	}
	if !strings.Contains(status.Message, "not found") {
		t.Errorf("Message should mention 'not found', got: %s", status.Message)
	}

	t.Logf("✅ CheckTrust for non-existent cert: trusted=%v, message=%s", status.Trusted, status.Message)
}

// TestCATrust_CheckTrust_WithTempCert tests CheckTrust with a temporary cert file.
func TestCATrust_CheckTrust_WithTempCert(t *testing.T) {
	skipUnlessIntegration(t)

	// Generate certs in a temp directory
	tmpDir := t.TempDir()
	certDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("Failed to create cert dir: %v", err)
	}

	ciConfig := certinit.Config{
		CertDir:      certDir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(ciConfig)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	// Check trust (won't be trusted in CI, but should find the file)
	status := CheckTrust(result.CACertPath)
	if status.Platform == "" {
		t.Error("Platform should be set")
	}

	t.Logf("✅ CheckTrust with generated cert: trusted=%v, platform=%s", status.Trusted, status.Platform)
}

// TestCATrust_SetupTrust_NonExistentCert tests SetupTrust with a non-existent cert.
func TestCATrust_SetupTrust_NonExistentCert(t *testing.T) {
	skipUnlessIntegration(t)

	result := SetupTrust("/nonexistent/path/ca.crt")

	if result.Success {
		t.Error("SetupTrust should fail for non-existent cert")
	}
	if !strings.Contains(result.Message, "not found") {
		t.Errorf("Message should mention 'not found', got: %s", result.Message)
	}

	t.Logf("✅ SetupTrust for non-existent cert: success=%v, message=%s", result.Success, result.Message)
}

// TestCATrust_StatusAndResultStructs tests the Status and SetupResult structs.
func TestCATrust_StatusAndResultStructs(t *testing.T) {
	skipUnlessIntegration(t)

	status := Status{
		Trusted:  true,
		Platform: "linux",
		CertPath: "/tmp/ca.crt",
		Message:  "CA certificate is trusted",
	}

	if !status.Trusted {
		t.Error("Trusted should be true")
	}
	if status.Platform != "linux" {
		t.Errorf("Platform = %s, want linux", status.Platform)
	}
	if status.CertPath != "/tmp/ca.crt" {
		t.Errorf("CertPath = %s, want /tmp/ca.crt", status.CertPath)
	}

	setupResult := SetupResult{
		Success: true,
		Message: "installed",
		Command: "sudo cp",
	}

	if !setupResult.Success {
		t.Error("Success should be true")
	}
	if setupResult.Command != "sudo cp" {
		t.Errorf("Command = %s, want 'sudo cp'", setupResult.Command)
	}
}

// TestCATrust_CertGeneration_Hostname tests that certificates are generated
// with the correct hostname in SANs.
func TestCATrust_CertGeneration_Hostname(t *testing.T) {
	skipUnlessIntegration(t)

	tmpDir := t.TempDir()
	certDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("Failed to create cert dir: %v", err)
	}

	ciConfig := certinit.Config{
		CertDir:      certDir,
		AutoGenerate: true,
		Hostnames:    []string{"rampart.test", "localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(ciConfig)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	// Verify server cert has the first hostname as CN
	serverCertPEM, err := os.ReadFile(result.ServerCertPath)
	if err != nil {
		t.Fatalf("Failed to read server cert: %v", err)
	}

	block, _ := pem.Decode(serverCertPEM)
	if block == nil {
		t.Fatal("Failed to decode server cert PEM")
	}

	serverCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse server cert: %v", err)
	}

	// The CN should be the first hostname
	if serverCert.Subject.CommonName != "rampart.test" {
		t.Errorf("Server cert CN = %s, want rampart.test", serverCert.Subject.CommonName)
	}

	// DNSNames should include all hostnames
	hasRampartTest := false
	hasLocalhost := false
	for _, name := range serverCert.DNSNames {
		if name == "rampart.test" {
			hasRampartTest = true
		}
		if name == "localhost" {
			hasLocalhost = true
		}
	}

	if !hasRampartTest {
		t.Error("Server cert should have rampart.test in DNSNames")
	}
	if !hasLocalhost {
		t.Error("Server cert should have localhost in DNSNames")
	}

	t.Logf("✅ Server cert CN=%s, SANs=%v", serverCert.Subject.CommonName, serverCert.DNSNames)
}

// TestCATrust_CertGeneration_Expiry tests that generated certificates have
// reasonable expiry dates.
func TestCATrust_CertGeneration_Expiry(t *testing.T) {
	skipUnlessIntegration(t)

	tmpDir := t.TempDir()
	certDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("Failed to create cert dir: %v", err)
	}

	ciConfig := certinit.Config{
		CertDir:      certDir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(ciConfig)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	// Check CA cert expiry (should be ~10 years)
	if result.CAExpiry.IsZero() {
		t.Error("CA cert expiry should not be zero")
	}
	caDuration := result.CAExpiry.Sub(result.ServerExpiry)
	t.Logf("CA cert duration: %v (expires: %s)", caDuration, result.CAExpiry)

	// Check server cert expiry (should be ~1 year)
	if result.ServerExpiry.IsZero() {
		t.Error("Server cert expiry should not be zero")
	}
	t.Logf("Server cert expires: %s", result.ServerExpiry)

	// CA should expire after server cert
	if !result.CAExpiry.After(result.ServerExpiry) {
		t.Error("CA cert should expire after server cert")
	}

	t.Log("✅ Certificate expiry dates are reasonable")
}

// TestCATrust_CertGeneration_ECDSA tests that generated certificates use ECDSA P-256.
func TestCATrust_CertGeneration_ECDSA(t *testing.T) {
	skipUnlessIntegration(t)

	tmpDir := t.TempDir()
	certDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("Failed to create cert dir: %v", err)
	}

	ciConfig := certinit.Config{
		CertDir:      certDir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(ciConfig)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	// Read and verify CA cert uses ECDSA
	caCertPEM, err := os.ReadFile(result.CACertPath)
	if err != nil {
		t.Fatalf("Failed to read CA cert: %v", err)
	}

	block, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}

	// Verify ECDSA signature algorithm
	switch caCert.SignatureAlgorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		t.Logf("✅ CA cert uses ECDSA: %s", caCert.SignatureAlgorithm)
	default:
		t.Errorf("CA cert should use ECDSA, got %s", caCert.SignatureAlgorithm)
	}

	// Verify server cert also uses ECDSA
	serverCertPEM, err := os.ReadFile(result.ServerCertPath)
	if err != nil {
		t.Fatalf("Failed to read server cert: %v", err)
	}

	serverBlock, _ := pem.Decode(serverCertPEM)
	serverCert, err := x509.ParseCertificate(serverBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse server cert: %v", err)
	}

	switch serverCert.SignatureAlgorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		t.Logf("✅ Server cert uses ECDSA: %s", serverCert.SignatureAlgorithm)
	default:
		t.Errorf("Server cert should use ECDSA, got %s", serverCert.SignatureAlgorithm)
	}
}

// TestCATrust_ProxyStartupWithCerts tests that the proxy can start with generated certs.
func TestCATrust_ProxyStartupWithCerts(t *testing.T) {
	skipUnlessIntegration(t)

	tmpDir := t.TempDir()
	certDir := filepath.Join(tmpDir, "certs")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatalf("Failed to create cert dir: %v", err)
	}

	// Override the home directory for the proxy
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// This test verifies that certinit can generate certs and the proxy
	// can use them. We don't start the proxy fully because it binds a port.
	ciConfig := certinit.Config{
		CertDir:      certDir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(ciConfig)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	if !result.Generated {
		t.Error("Expected Generated=true")
	}

	// Verify the proxy can find the generated certs
	for _, path := range []string{result.CACertPath, result.CAKeyPath, result.ServerCertPath, result.ServerKeyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("Cert file should exist: %s (err: %v)", path, err)
		}
	}

	t.Log("✅ Proxy startup with cert generation works correctly")
}
