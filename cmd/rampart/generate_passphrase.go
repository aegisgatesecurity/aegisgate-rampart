// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Passphrase Generation Command
// =========================================================================
//
// CLI command to generate a cryptographically secure random passphrase
// for encrypting audit logs. The passphrase is generated using
// crypto/rand and is suitable for use with --audit-key-passphrase.
//
// Usage:
//   rampart generate-passphrase
//   rampart generate-passphrase --length=32
// =========================================================================

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/auditlog"
)

// runGeneratePassphrase generates a secure random passphrase
func runGeneratePassphrase(length int) error {
	if length < 16 {
		return fmt.Errorf("passphrase length must be at least 16 characters (recommended: 32+)")
	}

	if length > 128 {
		return fmt.Errorf("passphrase length must be at most 128 characters")
	}

	// Generate passphrase using the same function as encryption
	passphrase, err := auditlog.GenerateRandomPassphrase()
	if err != nil {
		return fmt.Errorf("generating passphrase: %w", err)
	}

	// Truncate to requested length if needed
	if len(passphrase) > length {
		passphrase = passphrase[:length]
	}

	fmt.Printf("Generated Secure Passphrase\n")
	fmt.Printf("===========================\n\n")
	// Intentionally printed to stdout — this is a passphrase generation
	// command. The user must see the passphrase to use it. This is NOT
	// logging of sensitive data; it is the primary output of the command.
	// codeql[go/clear-text-logging]
	fmt.Printf("%s\n\n", passphrase)
	fmt.Printf("⚠️  CRITICAL SECURITY INSTRUCTIONS:\n")
	fmt.Printf("   1. Store this passphrase in a secure password manager\n")
	fmt.Printf("   2. NEVER store it in plain text or commit to version control\n")
	fmt.Printf("   3. Use with: rampart --audit-key-passphrase=\"<passphrase>\"\n")
	fmt.Printf("   4. Decryption requires THIS EXACT passphrase\n")
	fmt.Printf("   5. If lost, encrypted logs CANNOT be recovered\n")
	fmt.Printf("\nExample usage:\n")
	// codeql[go/clear-text-logging]
	fmt.Printf("   rampart --audit-key-passphrase=\"%s\"\n", passphrase)

	return nil
}

// handleGeneratePassphrase handles the generate-passphrase subcommand
func handleGeneratePassphrase(args []string) {
	// Parse length flag for this subcommand
	lengthFlag := flag.NewFlagSet("generate-passphrase", flag.ExitOnError)
	length := lengthFlag.Int("length", 32, "Passphrase length (16-128 characters)")

	if err := lengthFlag.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if err := runGeneratePassphrase(*length); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
