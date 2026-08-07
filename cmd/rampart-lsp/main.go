// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — LSP Server Entry Point
// =========================================================================
// CLI entry point for the Rampart LSP server.
// Communicates over stdio using JSON-RPC 2.0.
// =========================================================================

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/lsp"
)

func main() {
	rampartURL := flag.String("rampart-url", "http://localhost:9090", "URL of the Rampart /detect endpoint")
	debounceMs := flag.Int("debounce-ms", 300, "Milliseconds to debounce before calling /detect after text changes")
	minSeverity := flag.String("min-severity", "medium", "Minimum severity to report (critical, high, medium, low)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("rampart-lsp dev")
		os.Exit(0)
	}

	// Validate min-severity
	threshold := lsp.SeverityThreshold(*minSeverity)
	switch threshold {
	case lsp.ThresholdCritical, lsp.ThresholdHigh, lsp.ThresholdMedium, lsp.ThresholdLow:
		// Valid
	default:
		fmt.Fprintf(os.Stderr, "rampart-lsp: invalid min-severity %q (must be critical, high, medium, or low)\n", *minSeverity)
		os.Exit(1)
	}

	client := lsp.NewRampartClient(*rampartURL)
	handler := lsp.NewHandler(client, *debounceMs, threshold)
	server := lsp.NewServer(handler)

	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "rampart-lsp: %v\n", err)
		os.Exit(1)
	}
}
