// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigPath(t *testing.T) {
	path := ConfigPath()
	if path == "" {
		t.Error("ConfigPath() returned empty string")
	}
	if filepath.Base(path) != "config.json" {
		t.Errorf("expected config.json basename, got %s", filepath.Base(path))
	}
}

func TestReloadPreservesDefaults(t *testing.T) {
	// Load default config
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify defaults are intact
	if cfg.ProxyPort != 8080 {
		t.Errorf("expected ProxyPort 8080, got %d", cfg.ProxyPort)
	}
	if len(cfg.Targets) == 0 {
		t.Error("expected non-empty targets")
	}
	if cfg.Privacy.NoPromptText != true {
		t.Error("privacy NoPromptText should default to true")
	}
}

func TestLoadFromTempDir(t *testing.T) {
	tmpDir := t.TempDir()
	configData := `{
		"proxy_port": 9999,
		"daemon_mode": true,
		"targets": [
			{"domain": "api.test.example.com", "paths": ["/v1/*"], "description": "Test"}
		],
		"privacy": {
			"no_prompt_text": true,
			"no_urls": true
		}
	}`
	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.ProxyPort != 9999 {
		t.Errorf("expected proxy_port 9999, got %d", cfg.ProxyPort)
	}
	if !cfg.DaemonMode {
		t.Error("expected daemon_mode true")
	}
	if len(cfg.Targets) != 1 {
		t.Errorf("expected 1 target, got %d", len(cfg.Targets))
	}
	if cfg.Targets[0].Domain != "api.test.example.com" {
		t.Errorf("expected api.test.example.com, got %s", cfg.Targets[0].Domain)
	}
}
