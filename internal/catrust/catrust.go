// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - CA Trust Setup
// =========================================================================
//
// Guided CA certificate trust setup for HTTPS interception.
// Walks the user through installing the Rampart CA certificate
// into their OS/browser trust store so that MITM interception
// of AI API traffic works without certificate errors.
//
// Platform support:
//   - macOS:   security add-trusted-cert (Keychain)
//   - Linux:   cp to /usr/local/share/ca-certificates/ + update-ca-certificates
//   - Windows: certutil -addstore (Trusted Root CAs)
//
// =========================================================================

package catrust

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/platform"
)

// Status represents the trust status of the CA certificate.
type Status struct {
	Trusted  bool   `json:"trusted"`
	Platform string `json:"platform"`
	CertPath string `json:"cert_path"`
	Message  string `json:"message"`
}

// SetupResult contains the result of a trust setup operation.
type SetupResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Command string `json:"command,omitempty"`
}

// CheckTrust checks if the CA certificate is trusted by the system.
func CheckTrust(certPath string) Status {
	status := Status{
		Platform: runtime.GOOS,
		CertPath: certPath,
	}

	if _, err := os.Stat(certPath); err != nil {
		status.Message = "CA certificate not found. Run rampart first to generate it."
		return status
	}

	switch runtime.GOOS {
	case "darwin":
		return checkTrustDarwin(certPath)
	case "linux":
		return checkTrustLinux(certPath)
	case "windows":
		return checkTrustWindows(certPath)
	default:
		status.Message = fmt.Sprintf("Unsupported platform: %s", runtime.GOOS)
		return status
	}
}

// SetupTrust installs the CA certificate into the system trust store.
// Requires elevated privileges on most platforms.
func SetupTrust(certPath string) SetupResult {
	if _, err := os.Stat(certPath); err != nil {
		return SetupResult{
			Success: false,
			Message: fmt.Sprintf("CA certificate not found at %s", certPath),
		}
	}

	switch runtime.GOOS {
	case "darwin":
		return setupTrustDarwin(certPath)
	case "linux":
		return setupTrustLinux(certPath)
	case "windows":
		return setupTrustWindows(certPath)
	default:
		return SetupResult{
			Success: false,
			Message: fmt.Sprintf("Unsupported platform: %s", runtime.GOOS),
		}
	}
}

// GetInstructions returns human-readable instructions for manual trust setup.
func GetInstructions(certPath string) string {
	var sb strings.Builder
	sb.WriteString("=== AegisGate Rampart — CA Certificate Trust Setup ===\n\n")
	sb.WriteString(fmt.Sprintf("CA certificate: %s\n\n", certPath))

	switch runtime.GOOS {
	case "darwin":
		sb.WriteString("macOS — Automatic setup (requires sudo):\n")
		sb.WriteString(fmt.Sprintf("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n\n", certPath))
		sb.WriteString("macOS — Manual setup:\n")
		sb.WriteString("  1. Double-click the certificate file\n")
		sb.WriteString("  2. Open Keychain Access\n")
		sb.WriteString("  3. Find 'AegisGate CA' in the System keychain\n")
		sb.WriteString("  4. Double-click it, expand 'Trust', set to 'Always Trust'\n")

	case "linux":
		dest := "/usr/local/share/ca-certificates/aegisgate-rampart-ca.crt"
		sb.WriteString("Linux — Automatic setup (requires sudo):\n")
		sb.WriteString(fmt.Sprintf("  sudo cp %s %s\n", certPath, dest))
		sb.WriteString("  sudo update-ca-certificates\n\n")
		sb.WriteString("Firefox — Manual setup:\n")
		sb.WriteString("  1. Open Settings → Privacy & Security → Certificates\n")
		sb.WriteString("  2. Click 'View Certificates' → Authorities → Import\n")
		sb.WriteString(fmt.Sprintf("  3. Select %s\n", certPath))
		sb.WriteString("  4. Check 'Trust this CA to identify websites'\n")

	case "windows":
		sb.WriteString("Windows — Automatic setup (requires admin):\n")
		sb.WriteString(fmt.Sprintf("  certutil -addstore -user Root %s\n\n", certPath))
		sb.WriteString("Windows — Manual setup:\n")
		sb.WriteString("  1. Double-click the certificate file\n")
		sb.WriteString("  2. Click 'Install Certificate' → 'Local Machine'\n")
		sb.WriteString("  3. Select 'Trusted Root Certification Authorities'\n")
		sb.WriteString("  4. Complete the wizard\n")
	}

	sb.WriteString("\n⚠️  After trusting the CA certificate, restart your browser for changes to take effect.\n")
	return sb.String()
}

// --- macOS ---

func checkTrustDarwin(certPath string) Status {
	status := Status{Trusted: false, Platform: "darwin", CertPath: certPath}
	// Check if cert is in the System keychain
	cmd := exec.Command("security", "find-certificate", "-c", "AegisGate CA", "/Library/Keychains/System.keychain")
	if cmd.Run() == nil {
		status.Trusted = true
		status.Message = "CA certificate is trusted (System keychain)"
	} else {
		status.Message = "CA certificate is NOT trusted. Run 'rampart trust' to install it."
	}
	return status
}

func setupTrustDarwin(certPath string) SetupResult {
	cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return SetupResult{
			Success: false,
			Message: fmt.Sprintf("Failed to install CA certificate: %s\n%s", err, string(output)),
			Command: cmd.String(),
		}
	}
	return SetupResult{
		Success: true,
		Message: "CA certificate installed and trusted in macOS System keychain",
		Command: cmd.String(),
	}
}

// --- Linux ---

func checkTrustLinux(certPath string) Status {
	status := Status{Trusted: false, Platform: "linux", CertPath: certPath}
	// Check if cert exists in the system trust store
	dest := "/usr/local/share/ca-certificates/aegisgate-rampart-ca.crt"
	if _, err := os.Stat(dest); err == nil {
		status.Trusted = true
		status.Message = "CA certificate is trusted (system trust store)"
	} else {
		status.Message = "CA certificate is NOT trusted. Run 'rampart trust' to install it."
	}
	return status
}

func setupTrustLinux(certPath string) SetupResult {
	dest := "/usr/local/share/ca-certificates/aegisgate-rampart-ca.crt"
	cmd := exec.Command("sudo", "cp", certPath, dest)
	if output, err := cmd.CombinedOutput(); err != nil {
		return SetupResult{
			Success: false,
			Message: fmt.Sprintf("Failed to copy certificate: %s\n%s", err, string(output)),
			Command: cmd.String(),
		}
	}
	cmd = exec.Command("sudo", "update-ca-certificates")
	if output, err := cmd.CombinedOutput(); err != nil {
		return SetupResult{
			Success: false,
			Message: fmt.Sprintf("Failed to update CA certificates: %s\n%s", err, string(output)),
			Command: cmd.String(),
		}
	}
	return SetupResult{
		Success: true,
		Message: "CA certificate installed and trusted in Linux system trust store",
		Command: fmt.Sprintf("sudo cp %s %s && sudo update-ca-certificates", certPath, dest),
	}
}

// --- Windows ---

func checkTrustWindows(certPath string) Status {
	status := Status{Trusted: false, Platform: "windows", CertPath: certPath}
	cmd := exec.Command("certutil", "-store", "-user", "Root", "AegisGate CA")
	if cmd.Run() == nil {
		status.Trusted = true
		status.Message = "CA certificate is trusted (Windows certificate store)"
	} else {
		status.Message = "CA certificate is NOT trusted. Run 'rampart trust' to install it."
	}
	return status
}

func setupTrustWindows(certPath string) SetupResult {
	cmd := exec.Command("certutil", "-addstore", "-user", "Root", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return SetupResult{
			Success: false,
			Message: fmt.Sprintf("Failed to install CA certificate: %s\n%s", err, string(output)),
			Command: cmd.String(),
		}
	}
	return SetupResult{
		Success: true,
		Message: "CA certificate installed and trusted in Windows certificate store",
		Command: cmd.String(),
	}
}

// DefaultCACertPath returns the default CA certificate path for the current platform.
func DefaultCACertPath() string {
	return filepath.Join(platform.ConfigDir(), "ca.crt")
}
