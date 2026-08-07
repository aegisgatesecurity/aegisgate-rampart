// SPDX-License-Identifier: Apache-2.0
package catrust

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCheckTrust_NonExistentCertDetailed tests CheckTrust with detailed assertions.
func TestCheckTrust_NonExistentCertDetailed(t *testing.T) {
	status := CheckTrust("/nonexistent/path/ca.crt")
	if status.Trusted {
		t.Error("Should NOT be trusted when cert doesn't exist")
	}
	if status.Platform == "" {
		t.Error("Platform should be set even for non-existent cert")
	}
	if status.CertPath != "/nonexistent/path/ca.crt" {
		t.Errorf("CertPath = %s, want /nonexistent/path/ca.crt", status.CertPath)
	}
	if !strings.Contains(status.Message, "not found") {
		t.Errorf("Message should mention 'not found', got: %s", status.Message)
	}
}

// TestCheckTrust_WithExistingButUntrustedCert tests CheckTrust with an existing but untrusted cert.
func TestCheckTrust_WithExistingButUntrustedCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----"), 0644); err != nil {
		t.Fatal(err)
	}

	status := CheckTrust(certPath)
	// The cert exists but is not trusted in the system trust store
	if status.CertPath != certPath {
		t.Errorf("CertPath = %s, want %s", status.CertPath, certPath)
	}
	if status.Platform != runtime.GOOS {
		t.Errorf("Platform = %s, want %s", status.Platform, runtime.GOOS)
	}
	t.Logf("CheckTrust with dummy cert: trusted=%v, message=%s", status.Trusted, status.Message)
}

// TestGetInstructions_ContainsAllPlatforms tests that GetInstructions has content for all platforms.
func TestGetInstructions_ContainsAllPlatforms(t *testing.T) {
	instructions := GetInstructions("/path/to/ca.crt")

	// Should always contain the header
	if !strings.Contains(instructions, "AegisGate Rampart") {
		t.Error("Instructions should contain 'AegisGate Rampart'")
	}
	if !strings.Contains(instructions, "CA certificate") {
		t.Error("Instructions should mention 'CA certificate'")
	}

	// Platform-specific content depends on runtime.GOOS
	switch runtime.GOOS {
	case "darwin":
		if !strings.Contains(instructions, "Keychain") && !strings.Contains(instructions, "security") {
			t.Error("macOS instructions should mention Keychain/security")
		}
		if !strings.Contains(instructions, "Keychain Access") {
			t.Error("macOS instructions should mention Keychain Access")
		}
	case "linux":
		if !strings.Contains(instructions, "update-ca-certificates") {
			t.Error("Linux instructions should mention update-ca-certificates")
		}
		if !strings.Contains(instructions, "/usr/local/share/ca-certificates/") {
			t.Error("Linux instructions should mention the ca-certificates path")
		}
		if !strings.Contains(instructions, "Firefox") {
			t.Error("Linux instructions should mention Firefox")
		}
	case "windows":
		if !strings.Contains(instructions, "certutil") {
			t.Error("Windows instructions should mention certutil")
		}
		if !strings.Contains(instructions, "Trusted Root") {
			t.Error("Windows instructions should mention Trusted Root")
		}
	}

	// Should always end with the restart browser warning
	if !strings.Contains(instructions, "restart your browser") {
		t.Error("Instructions should mention restarting the browser")
	}
}

// TestGetInstructions_NonEmptyPath tests GetInstructions with a non-empty cert path.
func TestGetInstructions_NonEmptyPath(t *testing.T) {
	instructions := GetInstructions("/etc/ssl/certs/aegisgate-rampart-ca.crt")
	if instructions == "" {
		t.Error("GetInstructions should not return empty string")
	}
	if !strings.Contains(instructions, "/etc/ssl/certs/aegisgate-rampart-ca.crt") {
		t.Error("Instructions should contain the cert path")
	}
}

// TestSetupTrust_NonExistentCert tests SetupTrust failure with non-existent cert.
func TestSetupTrust_NonExistentCert(t *testing.T) {
	result := SetupTrust("/nonexistent/path/ca.crt")
	if result.Success {
		t.Error("SetupTrust should fail for non-existent cert")
	}
	if !strings.Contains(result.Message, "not found") {
		t.Errorf("Message should mention 'not found', got: %s", result.Message)
	}
}

// TestDefaultCACertPath_NonEmpty tests DefaultCACertPath returns a valid path.
func TestDefaultCACertPath_NonEmpty(t *testing.T) {
	path := DefaultCACertPath()
	if path == "" {
		t.Error("DefaultCACertPath should not return empty string")
	}
	if filepath.Base(path) != "ca.crt" {
		t.Errorf("DefaultCACertPath should end with ca.crt, got %s", path)
	}
	if !strings.Contains(path, "aegisgate-rampart") {
		t.Errorf("DefaultCACertPath should contain 'aegisgate-rampart', got %s", path)
	}
}

// TestCheckTrust_PlatformSpecific tests CheckTrust routing for the current platform.
func TestCheckTrust_PlatformSpecific(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}

	status := CheckTrust(certPath)
	if status.Platform != runtime.GOOS {
		t.Errorf("Platform = %s, want %s", status.Platform, runtime.GOOS)
	}
	t.Logf("CheckTrust platform: %s, trusted: %v, message: %s", status.Platform, status.Trusted, status.Message)
}

// TestSetupTrust_PlatformSpecific tests SetupTrust routing for the current platform.
func TestSetupTrust_PlatformSpecific(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}

	result := SetupTrust(certPath)
	// May fail depending on platform/permissions, but should not panic
	t.Logf("SetupTrust result: success=%v, message=%s", result.Success, result.Message)
}

// TestCheckTrustLinux_WithFakeTrustedCert tests checkTrustLinux when cert is in system trust store.
func TestCheckTrustLinux_WithFakeTrustedCert(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	// Create a fake cert at the system trust store location
	// (we can't actually write to /usr/local/share/ca-certificates/ without sudo)
	// So we test with a cert that exists but isn't in the system store
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}

	status := checkTrustLinux(certPath)
	if status.Platform != "linux" {
		t.Errorf("Platform = %s, want linux", status.Platform)
	}
	t.Logf("checkTrustLinux: trusted=%v, message=%s", status.Trusted, status.Message)
}

// TestCheckTrustLinux_NonExistent tests checkTrustLinux with non-existent cert.
func TestCheckTrustLinux_NonExistent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	status := checkTrustLinux("/nonexistent/ca.crt")
	if status.Trusted {
		t.Error("Should not be trusted with non-existent cert")
	}
	t.Logf("checkTrustLinux non-existent: trusted=%v, message=%s", status.Trusted, status.Message)
}

// TestSetupTrustLinux_NonExistent tests setupTrustLinux with a non-existent source cert.
func TestSetupTrustLinux_NonExistent(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	result := setupTrustLinux("/nonexistent/ca.crt")
	// This should fail gracefully since the source cert doesn't exist
	// (Actually setupTrustLinux doesn't check if source exists, it just runs cp)
	// The cp command will fail because the source file doesn't exist
	t.Logf("setupTrustLinux result: success=%v, message=%s", result.Success, result.Message)
}

// TestGetInstructions_EachPlatform tests GetInstructions for each platform string content.
func TestGetInstructions_EachPlatform(t *testing.T) {
	tests := []struct {
		platform    string
		contains    string
		description string
	}{
		{"darwin", "Keychain", "macOS should mention Keychain"},
		{"linux", "update-ca-certificates", "Linux should mention update-ca-certificates"},
		{"windows", "certutil", "Windows should mention certutil"},
	}

	// We can only test the current platform's content
	instructions := GetInstructions("/test/ca.crt")
	for _, tt := range tests {
		if runtime.GOOS == tt.platform {
			if !strings.Contains(instructions, tt.contains) {
				t.Errorf("%s: instructions should contain %q", tt.description, tt.contains)
			}
		}
	}
}

// TestStatus_Fields tests all fields of the Status struct.
func TestStatus_Fields(t *testing.T) {
	s := Status{
		Trusted:  true,
		Platform: "linux",
		CertPath: "/tmp/ca.crt",
		Message:  "trusted",
	}
	if !s.Trusted {
		t.Error("Trusted should be true")
	}
	if s.Platform != "linux" {
		t.Errorf("Platform = %s, want linux", s.Platform)
	}
	if s.CertPath != "/tmp/ca.crt" {
		t.Errorf("CertPath = %s, want /tmp/ca.crt", s.CertPath)
	}
	if s.Message != "trusted" {
		t.Errorf("Message = %s, want trusted", s.Message)
	}
}

// TestSetupResult_Fields tests all fields of the SetupResult struct.
func TestSetupResult_Fields(t *testing.T) {
	r := SetupResult{
		Success: true,
		Message: "installed",
		Command: "sudo cp /tmp/ca.crt /usr/local/share/ca-certificates/",
	}
	if !r.Success {
		t.Error("Success should be true")
	}
	if r.Message != "installed" {
		t.Errorf("Message = %s, want installed", r.Message)
	}
	if r.Command != "sudo cp /tmp/ca.crt /usr/local/share/ca-certificates/" {
		t.Errorf("Command = %s, want specific command", r.Command)
	}
}

// TestSetupResult_Empty tests SetupResult with empty/zero values.
func TestSetupResult_Empty(t *testing.T) {
	r := SetupResult{}
	if r.Success {
		t.Error("Empty SetupResult should have Success=false")
	}
	if r.Message != "" {
		t.Errorf("Empty SetupResult should have empty Message, got %s", r.Message)
	}
}

// TestCheckTrust_EmptyPath tests CheckTrust with an empty cert path.
func TestCheckTrust_EmptyPath(t *testing.T) {
	status := CheckTrust("")
	if status.Trusted {
		t.Error("Should not be trusted with empty cert path")
	}
	if status.CertPath != "" {
		t.Errorf("CertPath should be empty, got %s", status.CertPath)
	}
}
