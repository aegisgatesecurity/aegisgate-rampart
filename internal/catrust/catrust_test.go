package catrust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultCACertPath(t *testing.T) {
	path := DefaultCACertPath()
	if path == "" {
		t.Error("DefaultCACertPath should not be empty")
	}
	if filepath.Base(path) != "ca.crt" {
		t.Errorf("DefaultCACertPath should end with ca.crt, got %s", path)
	}
}

func TestCheckTrustNoCert(t *testing.T) {
	status := CheckTrust("/nonexistent/path/ca.crt")
	if status.Trusted {
		t.Error("Should not be trusted when cert doesn't exist")
	}
	if status.Platform == "" {
		t.Error("Platform should be set")
	}
}

func TestCheckTrustWithDummyCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}
	status := CheckTrust(certPath)
	// Won't be actually trusted but should find the file
	if status.Platform == "" {
		t.Error("Platform should be set")
	}
}

func TestGetInstructions(t *testing.T) {
	instructions := GetInstructions("/path/to/ca.crt")
	if instructions == "" {
		t.Error("GetInstructions should not be empty")
	}
	// Should contain platform-specific instructions
	if len(instructions) < 100 {
		t.Errorf("GetInstructions seems too short (%d bytes)", len(instructions))
	}
}

func TestSetupTrustNoCert(t *testing.T) {
	result := SetupTrust("/nonexistent/path/ca.crt")
	if result.Success {
		t.Error("SetupTrust should fail when cert doesn't exist")
	}
	if result.Message == "" {
		t.Error("Message should be set on failure")
	}
}

func TestStatusStruct(t *testing.T) {
	s := Status{Trusted: true, Platform: "linux", CertPath: "/tmp/ca.crt", Message: "trusted"}
	if !s.Trusted {
		t.Error("Trusted should be true")
	}
	if s.Platform != "linux" {
		t.Errorf("Platform = %s, want linux", s.Platform)
	}
}

func TestSetupResultStruct(t *testing.T) {
	r := SetupResult{Success: true, Message: "installed", Command: "sudo cp"}
	if !r.Success {
		t.Error("Success should be true")
	}
	if r.Command != "sudo cp" {
		t.Errorf("Command = %s", r.Command)
	}
}
