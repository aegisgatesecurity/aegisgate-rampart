// SPDX-License-Identifier: Apache-2.0
//go:build windows

package catrust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckTrustWindows_NonExistent(t *testing.T) {
	status := checkTrustWindows("/nonexistent/ca.crt")
	if status.Trusted {
		t.Error("Should not be trusted with non-existent cert")
	}
	if status.Platform != "windows" {
		t.Errorf("Platform = %s, want windows", status.Platform)
	}
}

func TestCheckTrustWindows_WithCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}

	status := checkTrustWindows(certPath)
	if status.Platform != "windows" {
		t.Errorf("Platform = %s, want windows", status.Platform)
	}
	t.Logf("checkTrustWindows: trusted=%v, message=%s", status.Trusted, status.Message)
}

func TestSetupTrustWindows_NonExistent(t *testing.T) {
	result := setupTrustWindows("/nonexistent/ca.crt")
	if result.Success {
		t.Error("SetupTrust should fail for non-existent cert")
	}
}

func TestSetupTrustWindows_WithCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}

	result := setupTrustWindows(certPath)
	t.Logf("setupTrustWindows: success=%v, message=%s", result.Success, result.Message)
}
