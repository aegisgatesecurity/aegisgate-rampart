// SPDX-License-Identifier: Apache-2.0

package catrust

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCompDefaultCACertPath(t *testing.T) {
	path := DefaultCACertPath()
	if path == "" {
		t.Error("DefaultCACertPath should not be empty")
	}
	if filepath.Base(path) != "ca.crt" {
		t.Errorf("DefaultCACertPath should end with ca.crt, got %s", path)
	}
	if !strings.Contains(path, ".config/aegisgate-rampart") {
		t.Errorf("DefaultCACertPath should contain .config/aegisgate-rampart, got %s", path)
	}
}

func TestCompCheckTrustNoCert(t *testing.T) {
	status := CheckTrust("/nonexistent/path/ca.crt")
	if status.Trusted {
		t.Error("Should not be trusted when cert doesn't exist")
	}
	if status.Platform == "" {
		t.Error("Platform should be set")
	}
	if status.CertPath != "/nonexistent/path/ca.crt" {
		t.Errorf("CertPath = %q, want /nonexistent/path/ca.crt", status.CertPath)
	}
	if !strings.Contains(status.Message, "not found") {
		t.Errorf("Message should mention not found: %q", status.Message)
	}
}

func TestCompCheckTrustWithDummyCert(t *testing.T) {
	t.Skip("System trust store check unreliable in CI")
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}
	status := CheckTrust(certPath)
	if status.Platform == "" {
		t.Error("Platform should be set")
	}
	if status.CertPath != certPath {
		t.Errorf("CertPath = %q, want %q", status.CertPath, certPath)
	}
	// On Linux, it checks a system path, so won't be trusted
	if runtime.GOOS == "linux" && status.Trusted {
		t.Error("Dummy cert should not be in system trust store")
	}
}

func TestCompGetInstructions(t *testing.T) {
	instructions := GetInstructions("/path/to/ca.crt")
	if instructions == "" {
		t.Error("GetInstructions should not be empty")
	}
	if len(instructions) < 100 {
		t.Errorf("GetInstructions seems too short (%d bytes)", len(instructions))
	}
	// Should contain the CA cert path
	if !strings.Contains(instructions, "/path/to/ca.crt") {
		t.Error("Instructions should contain the cert path")
	}
	// Should contain platform-specific instructions based on OS
	switch runtime.GOOS {
	case "darwin":
		if !strings.Contains(instructions, "Keychain") {
			t.Error("macOS instructions should mention Keychain")
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
	// Should always contain the restart warning
	if !strings.Contains(instructions, "restart your browser") {
		t.Error("Instructions should mention restarting browser")
	}
}

func TestCompSetupTrustNoCert(t *testing.T) {
	result := SetupTrust("/nonexistent/path/ca.crt")
	if result.Success {
		t.Error("SetupTrust should fail when cert doesn't exist")
	}
	if result.Message == "" {
		t.Error("Message should be set on failure")
	}
	if !strings.Contains(result.Message, "not found") {
		t.Errorf("Message should mention not found: %q", result.Message)
	}
}

func TestSetupTrustWithDummyCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}

	result := SetupTrust(certPath)
	// On most systems, this will fail because it requires elevated privileges
	// But we verify it doesn't panic and returns a meaningful result
	if result.Message == "" {
		t.Error("Message should be set")
	}
}

func TestCompStatusStruct(t *testing.T) {
	s := Status{Trusted: true, Platform: "linux", CertPath: "/tmp/ca.crt", Message: "trusted"}
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

func TestCompSetupResultStruct(t *testing.T) {
	r := SetupResult{Success: true, Message: "installed", Command: "sudo cp"}
	if !r.Success {
		t.Error("Success should be true")
	}
	if r.Command != "sudo cp" {
		t.Errorf("Command = %s", r.Command)
	}
	if r.Message != "installed" {
		t.Errorf("Message = %s", r.Message)
	}
}

func TestCheckTrustPlatformField(t *testing.T) {
	status := CheckTrust("/nonexistent/ca.crt")
	if status.Platform != runtime.GOOS {
		t.Errorf("Platform = %q, want %q", status.Platform, runtime.GOOS)
	}
}

func TestGetInstructionsContainsTitle(t *testing.T) {
	instructions := GetInstructions("/test/ca.crt")
	if !strings.Contains(instructions, "AegisGate Rampart") {
		t.Error("Instructions should contain title 'AegisGate Rampart'")
	}
	if !strings.Contains(instructions, "CA Certificate Trust Setup") {
		t.Error("Instructions should contain 'CA Certificate Trust Setup'")
	}
}

func TestSetupResultFailureFields(t *testing.T) {
	r := SetupResult{
		Success: false,
		Message: "CA certificate not found at /bad/path",
	}
	if r.Success {
		t.Error("Success should be false")
	}
	if !strings.Contains(r.Message, "not found") {
		t.Errorf("Message should contain 'not found': %q", r.Message)
	}
}

func TestDefaultCACertPathFormat(t *testing.T) {
	path := DefaultCACertPath()
	// Should follow XDG config pattern
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("Cannot determine home directory")
	}
	expected := filepath.Join(home, ".config", "aegisgate-rampart", "ca.crt")
	if path != expected {
		t.Errorf("DefaultCACertPath = %q, want %q", path, expected)
	}
}
