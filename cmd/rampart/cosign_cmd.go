// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart - Cosign CLI Commands

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/verify"
)

func runCosignCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("cosign subcommand required: verify, generate-key, sign")
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "verify":
		return runCosignVerify(subargs)
	case "generate-key":
		return runCosignGenerateKey(subargs)
	case "sign":
		return runCosignSign(subargs)
	case "version":
		return runCosignVersion(subargs)
	default:
		return fmt.Errorf("unknown cosign subcommand: %s", subcmd)
	}
}

func runCosignVerify(args []string) error {
	fs := flag.NewFlagSet("cosign verify", flag.ExitOnError)
	key := fs.String("key", "", "Public key file (required)")
	signature := fs.String("signature", "", "Signature file (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *key == "" || *signature == "" {
		return fmt.Errorf("-key and -signature are required")
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("binary path required")
	}

	binaryPath := fs.Arg(0)

	// Check if cosign is installed
	if !verify.IsCosignInstalled() {
		return fmt.Errorf("cosign CLI not found. Install from: https://docs.sigstore.dev/system_config/installation/")
	}

	// Verify signature
	result, err := verify.VerifyWithCosignCLI(binaryPath, *signature, *key)
	if err != nil {
		return err
	}

	if result.Valid {
		fmt.Printf("✅ Signature verification PASSED\n")
		fmt.Printf("   Binary: %s\n", binaryPath)
		fmt.Printf("   Key: %s\n", *key)
		if result.Output != "" {
			fmt.Printf("   Output: %s\n", result.Output)
		}
		return nil
	} else {
		fmt.Printf("❌ Signature verification FAILED\n")
		fmt.Printf("   Binary: %s\n", binaryPath)
		fmt.Printf("   Key: %s\n", *key)
		fmt.Printf("   Error: %v\n", result.Error)
		os.Exit(1)
		return nil
	}
}

func runCosignGenerateKey(args []string) error {
	fs := flag.NewFlagSet("cosign generate-key", flag.ExitOnError)
	output := fs.String("output", "", "Output directory (default: current directory)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	outputDir := *output
	if outputDir == "" {
		outputDir = "."
	}

	// Check if cosign is installed
	if !verify.IsCosignInstalled() {
		return fmt.Errorf("cosign CLI not found. Install from: https://docs.sigstore.dev/system_config/installation/")
	}

	// Generate keypair
	pubKey, privKey, err := verify.GenerateKeyPair(outputDir)
	if err != nil {
		return err
	}

	fmt.Printf("✅ Keypair generated successfully\n")
	fmt.Printf("   Public key: %s\n", pubKey)
	fmt.Printf("   Private key: %s\n", privKey)
	fmt.Printf("\n⚠️  IMPORTANT: Keep your private key secure!\n")
	fmt.Printf("   Never share cosign.key or commit it to version control.\n")

	return nil
}

func runCosignSign(args []string) error {
	fs := flag.NewFlagSet("cosign sign", flag.ExitOnError)
	key := fs.String("key", "", "Private key file (required)")
	output := fs.String("output", "", "Output signature file (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *key == "" || *output == "" {
		return fmt.Errorf("-key and -output are required")
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("binary path required")
	}

	binaryPath := fs.Arg(0)

	// Check if cosign is installed
	if !verify.IsCosignInstalled() {
		return fmt.Errorf("cosign CLI not found. Install from: https://docs.sigstore.dev/system_config/installation/")
	}

	// Sign the binary
	err := verify.SignBinary(binaryPath, *key, *output)
	if err != nil {
		return err
	}

	fmt.Printf("✅ Binary signed successfully\n")
	fmt.Printf("   Binary: %s\n", binaryPath)
	fmt.Printf("   Signature: %s\n", *output)
	fmt.Printf("   Key: %s\n", *key)

	return nil
}

func runCosignVersion(args []string) error {
	if !verify.IsCosignInstalled() {
		fmt.Println("cosign CLI not installed")
		fmt.Println("Install from: https://docs.sigstore.dev/system_config/installation/")
		os.Exit(1)
	}

	version, err := verify.GetCosignVersion()
	if err != nil {
		return err
	}

	fmt.Printf("cosign version: %s\n", version)
	return nil
}

// Helper function to get user's home directory for key storage
func getDefaultKeyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".aegisgate-rampart", "keys")
}
