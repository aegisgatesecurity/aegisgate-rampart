// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Config Integrity CLI
// =========================================================================
//
// Commands for managing configuration file integrity:
//   - config-hash: Generate hash record for config files
//   - config-verify: Verify config files against hash record
//   - config-check: Check for config changes
// =========================================================================

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/integrity"
)

const (
	configHashHelp = `Usage: rampart config-hash [options] <config-file...>

Generate SHA-256 hash record for one or more configuration files.

Options:
  -output <file>      Output file for hash record (default: stdout)
  -comment <text>     Comment to include in record
  -strict             Fail on missing files

Examples:
  # Generate hash for single config
  rampart config-hash ~/.config/aegisgate-rampart/config.json

  # Generate hash for multiple configs
  rampart config-hash config.json configs/prod.json --output hashes.json

  # With comment
  rampart config-hash config.json --comment "Production config v1.0"
`

	configVerifyHelp = `Usage: rampart config-verify <config-file> [options]

Verify a configuration file against an expected hash.

Options:
  -hash <sha256>      Expected SHA-256 hash (required)
  -record <file>      Hash record file (alternative to -hash)
  -json               Output results in JSON format
  -strict             Fail on verification errors

Examples:
  # Verify with inline hash
  rampart config-verify config.json --hash abc123...

  # Verify against record file
  rampart config-verify config.json --record hashes.json

  # JSON output
  rampart config-verify config.json --hash abc123... --json
`

	configCheckHelp = `Usage: rampart config-check <hash-record.json>

Check configuration files for unauthorized changes.

Options:
  -json               Output results in JSON format
  -strict             Fail if any changes detected

Examples:
  # Check all configs in record
  rampart config-check hashes.json

  # JSON output for automation
  rampart config-check hashes.json --json
`
)

func runConfigHash(args []string) error {
	fs := flag.NewFlagSet("config-hash", flag.ContinueOnError)
	outputFile := fs.String("output", "", "Output file for hash record")
	comment := fs.String("comment", "", "Comment to include")
	strictMode := fs.Bool("strict", false, "Fail on missing files")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, configHashHelp)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	configPaths := fs.Args()
	if len(configPaths) == 0 {
		fmt.Fprint(os.Stderr, configHashHelp)
		return fmt.Errorf("at least one config file required")
	}

	verifier := integrity.NewVerifier(*strictMode)
	record, err := verifier.GenerateHashRecord(configPaths, *comment)
	if err != nil {
		return err
	}

	if len(record.Configs) == 0 {
		return fmt.Errorf("no config files processed")
	}

	// Output
	if *outputFile != "" {
		if err := verifier.SaveHashRecord(record, *outputFile); err != nil {
			return err
		}
		fmt.Printf("✅ Hash record saved to: %s\n", *outputFile)
		fmt.Printf("   Files: %d\n", len(record.Configs))
		fmt.Printf("   Generated: %s\n", record.Generated.Format(time.RFC3339))
	} else {
		data, _ := json.MarshalIndent(record, "", "  ")
		fmt.Println(string(data))
	}

	return nil
}

func runConfigVerify(args []string) error {
	// Extract config path (first non-flag argument)
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, configVerifyHelp)
		return fmt.Errorf("config file path required")
	}

	configPath := ""
	flagArgs := make([]string, 0)

	for i, arg := range args {
		if i == 0 && len(arg) > 0 && arg[0] != '-' {
			configPath = arg
			continue
		}
		flagArgs = append(flagArgs, arg)
	}

	if configPath == "" {
		fmt.Fprint(os.Stderr, configVerifyHelp)
		return fmt.Errorf("config file path required")
	}

	fs := flag.NewFlagSet("config-verify", flag.ContinueOnError)
	expectedHash := fs.String("hash", "", "Expected SHA-256 hash")
	recordFile := fs.String("record", "", "Hash record file")
	jsonOutput := fs.Bool("json", false, "Output JSON format")
	strictMode := fs.Bool("strict", false, "Fail on errors")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, configVerifyHelp)
	}

	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	if *expectedHash == "" && *recordFile == "" {
		return fmt.Errorf("either --hash or --record required")
	}

	verifier := integrity.NewVerifier(*strictMode)

	// Get expected hash
	hashToVerify := *expectedHash
	if *recordFile != "" {
		record, err := verifier.LoadHashRecord(*recordFile)
		if err != nil {
			return fmt.Errorf("loading record: %w", err)
		}
		// Find matching config in record
		found := false
		for _, config := range record.Configs {
			if config.FilePath == configPath ||
				strings.HasSuffix(configPath, config.FilePath) {
				hashToVerify = config.Hash
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("config not found in record: %s", configPath)
		}
	}

	result, err := verifier.VerifyHash(configPath, hashToVerify)

	if *jsonOutput {
		return printVerifyJSON(result)
	}

	printVerifyText(result)
	return err
}

func runConfigCheck(args []string) error {
	fs := flag.NewFlagSet("config-check", flag.ContinueOnError)
	jsonOutput := fs.Bool("json", false, "Output JSON format")
	strictMode := fs.Bool("strict", false, "Fail on changes")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, configCheckHelp)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		fmt.Fprint(os.Stderr, configCheckHelp)
		return fmt.Errorf("hash record file required")
	}

	recordPath := fs.Arg(0)

	verifier := integrity.NewVerifier(*strictMode)
	record, err := verifier.LoadHashRecord(recordPath)
	if err != nil {
		return fmt.Errorf("loading record: %w", err)
	}

	report, err := verifier.DetectChanges(record)
	if err != nil && *strictMode {
		return err
	}

	if *jsonOutput {
		return printCheckJSON(report)
	}

	printCheckText(report)
	return nil
}

func printVerifyText(result *integrity.IntegrityResult) {
	fmt.Println("🔒 Config Integrity Verification")
	fmt.Println("================================")
	fmt.Printf("Config:        %s\n", result.ConfigPath)
	fmt.Printf("Status:        %s\n", statusText(result.Valid))
	fmt.Printf("Algorithm:     SHA-256\n")
	fmt.Printf("Expected:      %.16s...\n", result.ExpectedSHA)
	fmt.Printf("Computed:      %.16s...\n", result.ComputedSHA)

	if result.Metadata != nil {
		fmt.Printf("\nFile Metadata:\n")
		fmt.Printf("  Size:          %d bytes\n", result.Metadata.FileSize)
		fmt.Printf("  Modified:      %s\n", result.Metadata.ModTime.Format(time.RFC3339))
		fmt.Printf("  Permissions:   %s\n", result.Metadata.Permissions)
	}

	if result.Valid {
		fmt.Println("\n✅ Config file integrity verified")
	} else {
		fmt.Println("\n❌ WARNING: Config file has been modified!")
		fmt.Println("   This could indicate unauthorized changes or tampering.")
		fmt.Println("   Review changes immediately and restore from backup if needed.")
	}
}

func printVerifyJSON(result *integrity.IntegrityResult) error {
	output := map[string]interface{}{
		"valid":         result.Valid,
		"config_path":   result.ConfigPath,
		"expected_hash": result.ExpectedSHA,
		"computed_hash": result.ComputedSHA,
		"timestamp":     result.Timestamp,
	}
	if result.Metadata != nil {
		output["metadata"] = result.Metadata
	}
	if result.Error != nil {
		output["error"] = result.Error.Error()
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func printCheckText(report *integrity.ChangeReport) {
	fmt.Println("🔒 Config Change Detection Report")
	fmt.Println("==================================")
	fmt.Printf("Timestamp:     %s\n", report.Timestamp.Format(time.RFC3339))
	fmt.Printf("Total Files:   %d\n", report.Summary.Total)
	fmt.Println()

	fmt.Println("Summary:")
	fmt.Printf("  ✅ Unchanged:  %d\n", report.Summary.Unchanged)
	fmt.Printf("  ⚠️  Modified:   %d\n", report.Summary.Modified)
	fmt.Printf("  ❌ Missing:    %d\n", report.Summary.Missing)
	fmt.Printf("  ⛔ Errors:     %d\n", report.Summary.Errors)
	fmt.Println()

	if len(report.Configs) > 0 {
		fmt.Println("Details:")
		for _, change := range report.Configs {
			icon := "✅"
			switch change.Status {
			case integrity.ChangeModified:
				icon = "⚠️"
			case integrity.ChangeMissing:
				icon = "❌"
			case integrity.ChangeError:
				icon = "⛔"
			}
			fmt.Printf("  %s %s (%s)\n", icon, change.Path, change.Status.String())
		}
	}

	if report.IsSecure() {
		fmt.Println("\n✅ All config files unchanged")
	} else {
		fmt.Println("\n❌ WARNING: Unauthorized changes detected!")
		fmt.Println("   Review and remediate immediately.")
	}
}

func printCheckJSON(report *integrity.ChangeReport) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func statusText(valid bool) string {
	if valid {
		return "✅ Valid"
	}
	return "❌ Invalid"
}
