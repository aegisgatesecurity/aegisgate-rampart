// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Binary Verification CLI
// =========================================================================
//
// Command-line interface for verifying Rampart binary integrity.
//
// Usage:
//   rampart verify <binary-path> --checksum <checksum-file> [--signature <sig-file>] [--key <pubkey>]
// =========================================================================

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/verify"
)

const verifyHelp = `Usage: rampart verify <binary-path> [options]

Verify the integrity of a Rampart binary using SHA-256 checksums and
optional signature verification.

Options:
  -checksum <file>    Path to checksum file (required)
  -signature <file>   Path to signature file (optional)
  -key <file>         Path to public key file (required with -signature)
  -strict             Enable strict mode (fail on signature warnings)
  -json               Output results in JSON format
  -trusted <key-id>   Add trusted key ID (can be repeated)

Examples:
  # Verify checksum only
  rampart verify rampart --checksum checksums.txt

  # Verify checksum and signature
  rampart verify rampart --checksum checksums.txt --signature rampart.sig --key rampart.pub

  # Strict mode with trusted keys
  rampart verify rampart --checksum checksums.txt --signature rampart.sig --key rampart.pub --strict --trusted abc123

  # JSON output
  rampart verify rampart --checksum checksums.txt --json

Exit Codes:
  0 - Verification successful
  1 - Verification failed (checksum mismatch, signature invalid)
  2 - Error (file not found, invalid format)
`

func runVerify(args []string) error {
	// Extract binary path (first non-flag argument)
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, verifyHelp)
		return fmt.Errorf("binary path required")
	}

	binaryPath := ""
	flagArgs := make([]string, 0)

	// Separate binary path from flags
	for i, arg := range args {
		if i == 0 && len(arg) > 0 && arg[0] != '-' {
			binaryPath = arg
			continue
		}
		flagArgs = append(flagArgs, arg)
	}

	if binaryPath == "" {
		fmt.Fprint(os.Stderr, verifyHelp)
		return fmt.Errorf("binary path required")
	}

	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	checksumFile := fs.String("checksum", "", "Path to checksum file (required)")
	signatureFile := fs.String("signature", "", "Path to signature file (optional)")
	publicKeyFile := fs.String("key", "", "Path to public key file")
	strictMode := fs.Bool("strict", false, "Enable strict mode")
	jsonOutput := fs.Bool("json", false, "Output JSON format")
	trustedKeys := fs.String("trusted", "", "Comma-separated trusted key IDs")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, verifyHelp)
	}

	if err := fs.Parse(flagArgs); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		fmt.Fprint(os.Stderr, verifyHelp)
		return err
	}

	if *checksumFile == "" {
		return fmt.Errorf("--checksum flag is required")
	}

	if (*signatureFile != "" && *publicKeyFile == "") || (*publicKeyFile != "" && *signatureFile == "") {
		return fmt.Errorf("--signature and --key must be used together")
	}

	// Create verifier
	verifier := verify.NewVerifier(*strictMode)

	// Add trusted keys
	if *trustedKeys != "" {
		for _, keyID := range splitKeys(*trustedKeys) {
			verifier.AddTrustedKey(keyID)
		}
	}

	// Perform verification
	result, err := verifier.Verify(binaryPath, *checksumFile, *signatureFile, *publicKeyFile)
	if err != nil {
		if *jsonOutput {
			return printJSONError(err)
		}
		return err
	}

	// Output results
	if *jsonOutput {
		return printJSONResult(result)
	}

	printTextResult(result)
	return nil
}

func printTextResult(result *verify.VerificationResult) {
	fmt.Println("✅ Binary Verification Results")
	fmt.Println("==============================")
	fmt.Printf("Binary:        %s\n", result.BinaryPath)
	fmt.Printf("Checksum:      %s\n", statusIcon(result.ChecksumValid))
	if result.SignatureValid {
		fmt.Printf("Signature:     %s\n", statusIcon(result.SignatureValid))
		fmt.Printf("Trusted:       %s\n", statusIcon(result.Trusted))
	} else {
		fmt.Printf("Signature:     (not verified)\n")
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\n⚠️  Warnings:")
		for _, warning := range result.Warnings {
			fmt.Printf("   - %s\n", warning)
		}
	}

	if result.ChecksumValid {
		fmt.Println("\n✅ Binary integrity verified successfully")
	}
}

func printJSONResult(result *verify.VerificationResult) error {
	output := map[string]interface{}{
		"success":         result.ChecksumValid,
		"binary_path":     result.BinaryPath,
		"checksum_valid":  result.ChecksumValid,
		"signature_valid": result.SignatureValid,
		"trusted":         result.Trusted,
		"warnings":        result.Warnings,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func printJSONError(err error) error {
	output := map[string]interface{}{
		"success": false,
		"error":   err.Error(),
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func statusIcon(valid bool) string {
	if valid {
		return "✅ Valid"
	}
	return "❌ Invalid"
}

func splitKeys(s string) []string {
	if s == "" {
		return nil
	}
	keys := make([]string, 0)
	for _, key := range strings.Split(s, ",") {
		key = strings.TrimSpace(key)
		if key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}
