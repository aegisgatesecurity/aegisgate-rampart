// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart — LLM Preset Commands

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/llm"
)

func runLLMList(args []string) error {
	fs := flag.NewFlagSet("llm list", flag.ExitOnError)
	format := fs.String("format", "table", "Output format: table, json")
	_ = fs.Parse(args)

	presets := llm.GetPresets()

	if *format == "json" {
		data, err := json.MarshalIndent(presets, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	// Table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tURL\tDESCRIPTION")
	_, _ = fmt.Fprintln(w, "----\t---\t-----------")

	for _, p := range presets {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.URL, p.Description)
	}
	_ = w.Flush()

	fmt.Printf("\nTotal: %d presets\n", len(presets))
	fmt.Println("\nAdd a preset with: rampart llm add <name>")
	fmt.Println("Example: rampart llm add ollama")

	return nil
}
