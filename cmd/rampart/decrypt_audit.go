// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Audit Log Decryption Command
// =========================================================================
//
// CLI command to decrypt encrypted audit logs. Requires the original
// passphrase used for encryption. The decryption key is derived from
// the passphrase and is never stored on disk.
//
// Usage:
//   rampart decrypt-audit --audit-key-passphrase="..." input.log.enc output.log
// =========================================================================

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/auditlog"
)

// runDecryptAudit decrypts an encrypted audit log file
func runDecryptAudit(passphrase, inputPath, outputPath string) error {
	if passphrase == "" {
		return fmt.Errorf("passphrase required: use --audit-key-passphrase flag")
	}

	if inputPath == "" {
		return fmt.Errorf("input file required: rampart decrypt-audit input.log.enc output.log")
	}

	if outputPath == "" {
		return fmt.Errorf("output file required: rampart decrypt-audit input.log.enc output.log")
	}

	// Create decryptor
	decryptor := auditlog.NewDecryptor(passphrase)

	// Decrypt the file
	if err := decryptor.DecryptFile(inputPath, outputPath); err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	fmt.Printf("✅ Successfully decrypted audit log\n")
	fmt.Printf("   Input:  %s\n", inputPath)
	fmt.Printf("   Output: %s\n", outputPath)
	fmt.Printf("\n⚠️  SECURITY WARNING: Decrypted logs contain sensitive data.\n")
	fmt.Printf("   Store securely and delete when no longer needed.\n")

	return nil
}

// handleDecryptAudit handles the decrypt-audit subcommand
func handleDecryptAudit(args []string) {
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: rampart decrypt-audit [options] <input.log.enc> <output.log>\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  --audit-key-passphrase  Passphrase used to encrypt the audit log\n")
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  rampart decrypt-audit --audit-key-passphrase=\"secret\" audit.log.enc decrypted.log\n")
		os.Exit(1)
	}

	inputPath := args[0]
	outputPath := args[1]

	// Get passphrase from flag
	passphrase := ""
	for i, arg := range args {
		if arg == "--audit-key-passphrase" && i+1 < len(args) {
			passphrase = args[i+1]
			break
		}
		if strings.HasPrefix(arg, "--audit-key-passphrase=") {
			passphrase = strings.TrimPrefix(arg, "--audit-key-passphrase=")
			break
		}
	}

	if err := runDecryptAudit(passphrase, inputPath, outputPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
