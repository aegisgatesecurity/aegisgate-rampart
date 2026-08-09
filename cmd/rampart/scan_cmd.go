// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart — Batch Scan Commands

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"path/filepath"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/scanner"
)

func runScan(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("path required")
	}

	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	output := fs.String("output", "", "Output file (JSON format)")
	format := fs.String("format", "table", "Output format: table, json")
	fs.Parse(args)

	path := fs.Arg(0)

	fmt.Printf("🔍 Scanning %s...\n", path)
	start := time.Now()

	result, err := scanner.ScanDir(path)
	if err != nil {
		return fmt.Errorf("scanning directory: %w", err)
	}

	elapsed := time.Since(start)
	fmt.Printf("✅ Scanned %d files in %v\n\n", result.TotalFiles, elapsed)

	if len(result.Detections) == 0 {
		fmt.Println("✅ No detections found")
		return nil
	}

	fmt.Printf("🚨 Found %d detections:\n\n", len(result.Detections))

	if *format == "json" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}

		if *output != "" {
			if err := os.WriteFile(*output, data, 0644); err != nil {
				return err
			}
			fmt.Printf("Results saved to %s\n", *output)
		} else {
			fmt.Println(string(data))
		}
		return nil
	}

	// Table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tLINE\tCATEGORY\tSEVERITY\tMESSAGE")
	fmt.Fprintln(w, "----\t----\t--------\t--------\t-------")

	for _, d := range result.Detections {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n",
			filepath.Base(d.File), d.Line, d.Category, d.Severity, d.Message)
	}
	w.Flush()

	fmt.Printf("\nTotal: %d detections in %d files\n", len(result.Detections), result.TotalFiles)

	return nil
}
