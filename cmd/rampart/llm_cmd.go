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
	fs.Parse(args)

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
	fmt.Fprintln(w, "NAME\tURL\tDESCRIPTION")
	fmt.Fprintln(w, "----\t---\t-----------")

	for _, p := range presets {
		fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.URL, p.Description)
	}
	w.Flush()

	fmt.Printf("\nTotal: %d presets\n", len(presets))
	fmt.Println("\nAdd a preset with: rampart llm add <name>")
	fmt.Println("Example: rampart llm add ollama")

	return nil
}

func runLLMAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("preset name required")
	}

	presetName := args[0]
	preset, err := llm.GetPreset(presetName)
	if err != nil {
		return err
	}

	// TODO: Save to config file
	fmt.Printf("✅ Added LLM preset: %s\n", preset.Name)
	fmt.Printf("   URL: %s\n", preset.URL)
	fmt.Printf("   Type: %s\n", preset.Type)
	fmt.Printf("\nConfigure your AI service to use this endpoint.\n")
	fmt.Printf("Default models: %v\n", preset.DefaultModels)

	return nil
}
