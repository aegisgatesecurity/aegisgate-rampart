// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart - Cosign Signature Verification (CLI-based)
//
// Verifies binary signatures using the cosign CLI tool.
// This approach avoids the heavy dependency tree of the cosign Go library.
//
// Prerequisites:
//   - cosign CLI installed (https://docs.sigstore.dev/system_config/installation/)
//   - Public key file available

package verify

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CosignCLIResult represents the result of cosign CLI verification
type CosignCLIResult struct {
	Valid      bool
	BinaryPath string
	KeyPath    string
	Output     string
	Error      error
}

// VerifyWithCosignCLI verifies a binary signature using the cosign CLI
//
// This function requires the cosign CLI to be installed and available in PATH.
// It calls: cosign verify-blob --key <keyPath> --signature <sigPath> <binaryPath>
func VerifyWithCosignCLI(binaryPath, signaturePath, keyPath string) (*CosignCLIResult, error) {
	result := &CosignCLIResult{
		BinaryPath: binaryPath,
		KeyPath:    keyPath,
	}

	// Check if cosign is installed
	_, err := exec.LookPath("cosign")
	if err != nil {
		result.Error = fmt.Errorf("cosign CLI not found in PATH. Install from: https://docs.sigstore.dev/system_config/installation/")
		return result, result.Error
	}

	// Build cosign command
	// cosign verify-blob --key <key> --signature <sig> <blob>
	cmd := exec.Command("cosign", "verify-blob",
		"--key", keyPath,
		"--signature", signaturePath,
		binaryPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		result.Valid = false
		result.Output = stderr.String()
		result.Error = fmt.Errorf("signature verification failed: %w", err)
		return result, nil // Verification failed, but command ran successfully
	}

	result.Valid = true
	result.Output = stdout.String()
	return result, nil
}

// GenerateKeyPair generates a new cosign keypair
//
// This function requires the cosign CLI to be installed.
// It calls: cosign generate-key-pair [output directory]
func GenerateKeyPair(outputDir string) (pubKeyPath, privKeyPath string, err error) {
	// Check if cosign is installed
	_, err = exec.LookPath("cosign")
	if err != nil {
		return "", "", fmt.Errorf("cosign CLI not found in PATH")
	}

	// Generate keypair
	// cosign generate-key-pair [directory]
	cmd := exec.Command("cosign", "generate-key-pair", outputDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return "", "", fmt.Errorf("generate keypair: %w: %s", err, stderr.String())
	}

	// Cosign creates: cosign.pub and cosign.key in the output directory
	pubKeyPath = filepath.Join(outputDir, "cosign.pub")
	privKeyPath = filepath.Join(outputDir, "cosign.key")

	// Verify keys were created
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("public key not created at %s", pubKeyPath)
	}
	if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("private key not created at %s", privKeyPath)
	}

	return pubKeyPath, privKeyPath, nil
}

// SignBinary signs a binary using cosign CLI
//
// This function requires the cosign CLI to be installed.
// It calls: cosign sign-blob --key <keyPath> <binaryPath>
func SignBinary(binaryPath, keyPath, outputSigPath string) error {
	// Check if cosign is installed
	_, err := exec.LookPath("cosign")
	if err != nil {
		return fmt.Errorf("cosign CLI not found in PATH")
	}

	// Sign the binary
	// cosign sign-blob --key <key> --output-signature <output> <blob>
	cmd := exec.Command("cosign", "sign-blob",
		"--key", keyPath,
		"--output-signature", outputSigPath,
		binaryPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("sign binary: %w: %s", err, stderr.String())
	}

	return nil
}

// IsCosignInstalled checks if the cosign CLI is available
func IsCosignInstalled() bool {
	_, err := exec.LookPath("cosign")
	return err == nil
}

// GetCosignVersion returns the installed cosign version
func GetCosignVersion() (string, error) {
	_, err := exec.LookPath("cosign")
	if err != nil {
		return "", fmt.Errorf("cosign not installed")
	}

	cmd := exec.Command("cosign", "version")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err = cmd.Run()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(stdout.String()), nil
}
