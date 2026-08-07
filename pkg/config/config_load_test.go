// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromTempDirWithCustomConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configJSON := `{
		"proxy_port": 9090,
		"daemon_mode": true,
		"verbose": true,
		"platform_url": "https://platform.example.com",
		"targets": [{"domain": "api.custom.com", "paths": ["/v1/*"], "description": "Custom"}],
		"models": {"path": "/custom/model.onnx", "threshold": 0.1, "shadow": false},
		"privacy": {"no_prompt_text": false, "no_urls": true}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.ProxyPort != 9090 {
		t.Errorf("ProxyPort = %d, want 9090", cfg.ProxyPort)
	}
	if !cfg.DaemonMode {
		t.Error("DaemonMode should be true")
	}
	if !cfg.Verbose {
		t.Error("Verbose should be true")
	}
	if cfg.PlatformURL != "https://platform.example.com" {
		t.Errorf("PlatformURL = %s", cfg.PlatformURL)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("Targets = %d, want 1", len(cfg.Targets))
	}
	if cfg.Targets[0].Domain != "api.custom.com" {
		t.Errorf("Target domain = %s", cfg.Targets[0].Domain)
	}
	if cfg.Targets[0].Description != "Custom" {
		t.Errorf("Target description = %s", cfg.Targets[0].Description)
	}
	if len(cfg.Targets[0].Paths) != 1 {
		t.Errorf("Target paths = %d", len(cfg.Targets[0].Paths))
	}
	if cfg.Models.Threshold != 0.1 {
		t.Errorf("Threshold = %f, want 0.1", cfg.Models.Threshold)
	}
	if cfg.Models.Shadow {
		t.Error("Shadow should be false")
	}
	if cfg.Privacy.NoPromptText {
		t.Error("NoPromptText should be false (overridden)")
	}
	if !cfg.Privacy.NoURLs {
		t.Error("NoURLs should be true (not overridden)")
	}
}

func TestLoadFromNonexistentDir(t *testing.T) {
	cfg, err := Load("/nonexistent/path/that/does/not/exist")
	if err != nil {
		t.Fatalf("Load from nonexistent dir should use defaults: %v", err)
	}
	if cfg.ProxyPort != 8080 {
		t.Errorf("Fallback ProxyPort = %d, want 8080", cfg.ProxyPort)
	}
	if len(cfg.Targets) != 27 {
		t.Errorf("Fallback targets = %d, want 27", len(cfg.Targets))
	}
}

func TestCompLoadEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load from empty dir failed: %v", err)
	}
	if cfg.ProxyPort != 8080 {
		t.Errorf("Loaded ProxyPort = %d, want 8080", cfg.ProxyPort)
	}
	if !cfg.Privacy.NoPII {
		t.Error("Privacy.NoPII should default to true")
	}
}

func TestCompLoadInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(`{invalid`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(tmpDir)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestLoadEmptyStringDir(t *testing.T) {
	// Empty dir should use home directory
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with empty dir failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}
	if cfg.ProxyPort != 8080 {
		t.Errorf("ProxyPort = %d, want 8080", cfg.ProxyPort)
	}
}

func TestAllTargetDomainsPresent(t *testing.T) {
	cfg := DefaultConfig()

	expectedDomains := []string{
		"api.openai.com", "chat.openai.com", "chatgpt.com",
		"api.anthropic.com", "claude.ai",
		"generativelanguage.googleapis.com", "gemini.google.com",
		"api.copilot.microsoft.com", "copilot.microsoft.com", "copilot.cloud.microsoft",
		"api.perplexity.ai", "perplexity.ai", "www.perplexity.ai",
		"api.x.ai", "grok.com", "www.grok.com",
		"codestral.mistral.ai", "api.mistral.ai", "chat.mistral.ai", "le-chat.mistral.ai",
		"api.deepseek.com", "chat.deepseek.com",
		"api.duck.ai", "duck.ai", "www.duck.ai",
		"meta.ai", "www.meta.ai",
	}

	domainSet := make(map[string]bool)
	for _, t := range cfg.Targets {
		domainSet[t.Domain] = true
	}

	for _, domain := range expectedDomains {
		if !domainSet[domain] {
			t.Errorf("Missing target domain: %s", domain)
		}
	}
}

func TestPrivacyConfigValues(t *testing.T) {
	cfg := DefaultConfig()

	// All 12 non-negotiables should default to true
	privacyFields := []struct {
		name  string
		value bool
	}{
		{"NoPromptText", cfg.Privacy.NoPromptText},
		{"NoURLs", cfg.Privacy.NoURLs},
		{"NoPageContent", cfg.Privacy.NoPageContent},
		{"NoPII", cfg.Privacy.NoPII},
		{"NoCredentials", cfg.Privacy.NoCredentials},
		{"NoFingerprinting", cfg.Privacy.NoFingerprinting},
		{"NoCrossSite", cfg.Privacy.NoCrossSite},
		{"NoProviderMeta", cfg.Privacy.NoProviderMeta},
		{"NoKeystroke", cfg.Privacy.NoKeystroke},
		{"NoMouse", cfg.Privacy.NoMouse},
		{"NoSessionIDs", cfg.Privacy.NoSessionIDs},
		{"NoIPAddresses", cfg.Privacy.NoIPAddresses},
	}

	trueCount := 0
	for _, pf := range privacyFields {
		if !pf.value {
			t.Errorf("Privacy.%s should be true by default", pf.name)
		} else {
			trueCount++
		}
	}
	if trueCount != 12 {
		t.Errorf("Expected all 12 privacy fields to be true, got %d", trueCount)
	}
}

func TestPrivacyConfigPartialOverride(t *testing.T) {
	tmpDir := t.TempDir()
	configJSON := `{
		"privacy": {
			"no_prompt_text": false,
			"no_pii": false,
			"no_credentials": false
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Privacy.NoPromptText {
		t.Error("NoPromptText should be false (overridden)")
	}
	if cfg.Privacy.NoPII {
		t.Error("NoPII should be false (overridden)")
	}
	if cfg.Privacy.NoCredentials {
		t.Error("NoCredentials should be false (overridden)")
	}
	if !cfg.Privacy.NoURLs {
		t.Error("NoURLs should remain true (not overridden)")
	}
	if !cfg.Privacy.NoPageContent {
		t.Error("NoPageContent should remain true (not overridden)")
	}
}

func TestModelConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Models.Path != "/opt/aegisgate/models/threat-detection.onnx" {
		t.Errorf("Default Path = %s", cfg.Models.Path)
	}
	if cfg.Models.Threshold != 0.05 {
		t.Errorf("Default Threshold = %f, want 0.05", cfg.Models.Threshold)
	}
	if !cfg.Models.Shadow {
		t.Error("Default Shadow should be true")
	}
}

func TestTargetConfigStruct(t *testing.T) {
	tc := TargetConfig{
		Domain:      "api.test.com",
		Paths:       []string{"/v1/*", "/v2/*"},
		Description: "Test API",
	}
	if tc.Domain != "api.test.com" {
		t.Errorf("Domain = %s", tc.Domain)
	}
	if len(tc.Paths) != 2 {
		t.Errorf("Paths = %d, want 2", len(tc.Paths))
	}
	if tc.Description != "Test API" {
		t.Errorf("Description = %s", tc.Description)
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := &Config{
		ProxyPort:   9999,
		DaemonMode:  true,
		Verbose:     true,
		PlatformURL: "https://test.example.com",
		Targets:     DefaultTargets(),
		Models:      ModelConfig{Path: "/test/model.onnx", Threshold: 0.5, Shadow: false},
		Privacy:     PrivacyConfig{NoPII: true},
	}
	if cfg.ProxyPort != 9999 {
		t.Errorf("ProxyPort = %d", cfg.ProxyPort)
	}
	if !cfg.DaemonMode {
		t.Error("DaemonMode should be true")
	}
	if !cfg.Verbose {
		t.Error("Verbose should be true")
	}
	if cfg.PlatformURL != "https://test.example.com" {
		t.Errorf("PlatformURL = %s", cfg.PlatformURL)
	}
}

func TestDefaultTargetsUnique(t *testing.T) {
	targets := DefaultTargets()
	seen := make(map[string]bool)
	for _, target := range targets {
		if seen[target.Domain] {
			t.Errorf("Duplicate target domain: %s", target.Domain)
		}
		seen[target.Domain] = true
	}
}

func TestDefaultTargetsHavePathsAndDescriptions(t *testing.T) {
	targets := DefaultTargets()
	for _, target := range targets {
		if len(target.Paths) == 0 {
			t.Errorf("Target %s has no paths", target.Domain)
		}
		if target.Description == "" {
			t.Errorf("Target %s has no description", target.Domain)
		}
	}
}

func TestLoadWithAllTargetOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configJSON := `{
		"targets": [
			{"domain": "custom.api.com", "paths": ["/api/*"], "description": "Custom API"},
			{"domain": "custom.web.com", "paths": ["/v1/*"], "description": "Custom Web"}
		]
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Targets) != 2 {
		t.Errorf("Expected 2 targets, got %d", len(cfg.Targets))
	}
	if cfg.Targets[0].Domain != "custom.api.com" {
		t.Errorf("First target domain = %s", cfg.Targets[0].Domain)
	}
}
