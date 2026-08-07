// SPDX-License-Identifier: Apache-2.0
//go:build darwin

package catrust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckTrustDarwin_NonExistent(t *testing.T) {
	status := checkTrustDarwin("/nonexistent/ca.crt")
	if status.Trusted {
		t.Error("Should not be trusted with non-existent cert")
	}
	if status.Platform != "darwin" {
		t.Errorf("Platform = %s, want darwin", status.Platform)
	}
}

func TestCheckTrustDarwin_WithCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}

	status := checkTrustDarwin(certPath)
	if status.Platform != "darwin" {
		t.Errorf("Platform = %s, want darwin", status.Platform)
	}
	t.Logf("checkTrustDarwin: trusted=%v, message=%s", status.Trusted, status.Message)
}

func TestSetupTrustDarwin_NonExistent(t *testing.T) {
	result := setupTrustDarwin("/nonexistent/ca.crt")
	if result.Success {
		t.Error("SetupTrust should fail for non-existent cert")
	}
}

func TestSetupTrustDarwin_WithCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}

	result := setupTrustDarwin(certPath)
	t.Logf("setupTrustDarwin: success=%v, message=%s", result.Success, result.Message)
}
