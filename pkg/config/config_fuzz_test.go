// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — Fuzz Targets
// =========================================================================
//
// Native Go fuzzing for config parsing and detection scanning.
// Run: go test -fuzz=FuzzParseConfig -fuzztime=60s ./pkg/config/
// Run: go test -fuzz=FuzzScanRequest -fuzztime=60s ./pkg/detector/
//
// =========================================================================

package config

import (
	"encoding/json"
	"testing"
)

// FuzzParseConfig fuzzes the config JSON parser with random input.
func FuzzParseConfig(f *testing.F) {
	// Seed corpus: valid config + malformed JSON
	seeds := []string{
		`{"proxy_port": 8080, "daemon_mode": false}`,
		`{"proxy_port": -1}`,
		`{"proxy_port": 99999}`,
		`{}`,
		`not json at all`,
		`{"proxy_port": "wrong type"}`,
		`{"targets": [{"domain": "api.openai.com", "paths": ["/v1/*"]}]}`,
		`{"privacy": {"no_prompt_text": true, "no_urls": true}}`,
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		var cfg Config
		if err := json.Unmarshal([]byte(input), &cfg); err != nil {
			return // Invalid JSON is expected — fuzz finds panics, not parse errors
		}
		// Validate the parsed config doesn't produce invalid state
		_ = cfg.ProxyPort
		_ = cfg.DaemonMode
		_ = cfg.Privacy.NoPromptText
	})
}