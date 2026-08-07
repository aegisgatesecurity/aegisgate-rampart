package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ProxyPort != 8080 {
		t.Errorf("Default ProxyPort = %d, want 8080", cfg.ProxyPort)
	}
	if cfg.DaemonMode {
		t.Error("Default DaemonMode should be false")
	}
	if cfg.Verbose {
		t.Error("Default Verbose should be false")
	}
	if cfg.PlatformURL != "" {
		t.Error("Default PlatformURL should be empty (air-gap)")
	}
	if len(cfg.Targets) != 27 {
		t.Errorf("Default targets = %d, want 27", len(cfg.Targets))
	}
	// 12 privacy non-negotiables all default to true
	if !cfg.Privacy.NoPromptText || !cfg.Privacy.NoURLs || !cfg.Privacy.NoPageContent {
		t.Error("Privacy non-negotiables should default to true")
	}
	if !cfg.Privacy.NoPII || !cfg.Privacy.NoCredentials || !cfg.Privacy.NoFingerprinting {
		t.Error("Privacy non-negotiables should default to true")
	}
	if !cfg.Privacy.NoCrossSite || !cfg.Privacy.NoProviderMeta || !cfg.Privacy.NoKeystroke {
		t.Error("Privacy non-negotiables should default to true")
	}
	if !cfg.Privacy.NoMouse || !cfg.Privacy.NoSessionIDs || !cfg.Privacy.NoIPAddresses {
		t.Error("Privacy non-negotiables should default to true")
	}
}

func TestDefaultTargets(t *testing.T) {
	targets := DefaultTargets()
	if len(targets) != 27 {
		t.Fatalf("DefaultTargets returned %d targets, want 27", len(targets))
	}

	// Verify all 10 providers are present
	providerDomains := map[string]bool{
		"api.openai.com":                    false,
		"chat.openai.com":                   false,
		"chatgpt.com":                       false,
		"api.anthropic.com":                 false,
		"claude.ai":                         false,
		"generativelanguage.googleapis.com": false,
		"gemini.google.com":                 false,
		"api.copilot.microsoft.com":         false,
		"copilot.microsoft.com":             false,
		"copilot.cloud.microsoft":           false,
		"api.perplexity.ai":                 false,
		"perplexity.ai":                     false,
		"www.perplexity.ai":                 false,
		"api.x.ai":                          false,
		"grok.com":                          false,
		"www.grok.com":                      false,
		"api.mistral.ai":                    false,
		"codestral.mistral.ai":              false,
		"chat.mistral.ai":                   false,
		"le-chat.mistral.ai":                false,
		"api.deepseek.com":                  false,
		"chat.deepseek.com":                 false,
		"api.duck.ai":                       false,
		"duck.ai":                           false,
		"www.duck.ai":                       false,
		"meta.ai":                           false,
		"www.meta.ai":                       false,
	}

	for _, target := range targets {
		if _, ok := providerDomains[target.Domain]; !ok {
			t.Errorf("Unexpected target domain: %s", target.Domain)
		}
		providerDomains[target.Domain] = true
		if len(target.Paths) == 0 {
			t.Errorf("Target %s has no paths", target.Domain)
		}
		if target.Description == "" {
			t.Errorf("Target %s has no description", target.Domain)
		}
	}

	for domain, found := range providerDomains {
		if !found {
			t.Errorf("Missing target domain: %s", domain)
		}
	}
}

func TestDefaultModelConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Models.Path != "/opt/aegisgate/models/threat-detection.onnx" {
		t.Errorf("Default Path = %s", cfg.Models.Path)
	}
	if cfg.Models.Threshold != 0.05 {
		t.Errorf("Default Threshold = %f, want 0.05", cfg.Models.Threshold)
	}
	if !cfg.Models.Shadow {
		t.Error("Default Shadow should be true (log but don't block)")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load from empty dir failed: %v", err)
	}
	if cfg.ProxyPort != 8080 {
		t.Errorf("Loaded ProxyPort = %d, want 8080", cfg.ProxyPort)
	}
}

func TestLoadCustomConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configJSON := `{
		"proxy_port": 9090,
		"daemon_mode": true,
		"verbose": true,
		"platform_url": "https://platform.example.com",
		"targets": [{"domain": "api.custom.com", "paths": ["/v1/*"], "description": "Custom"}],
		"models": {"path": "/custom/model.onnx", "threshold": 0.1, "shadow": false},
		"privacy": {"no_prompt_text": false}
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
	if cfg.Models.Threshold != 0.1 {
		t.Errorf("Threshold = %f, want 0.1", cfg.Models.Threshold)
	}
	if cfg.Models.Shadow {
		t.Error("Shadow should be false")
	}
	if cfg.Privacy.NoPromptText {
		t.Error("NoPromptText should be false (overridden)")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(`{invalid`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(tmpDir)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestLoadNonexistentDir(t *testing.T) {
	cfg, err := Load("/nonexistent/path/that/does/not/exist")
	if err != nil {
		t.Fatalf("Load from nonexistent dir should use defaults: %v", err)
	}
	if cfg.ProxyPort != 8080 {
		t.Errorf("Fallback ProxyPort = %d, want 8080", cfg.ProxyPort)
	}
}

func TestPrivacyNonNegotiablesCount(t *testing.T) {
	cfg := DefaultConfig()
	// Count the true fields — should be exactly 12
	count := 0
	if cfg.Privacy.NoPromptText {
		count++
	}
	if cfg.Privacy.NoURLs {
		count++
	}
	if cfg.Privacy.NoPageContent {
		count++
	}
	if cfg.Privacy.NoPII {
		count++
	}
	if cfg.Privacy.NoCredentials {
		count++
	}
	if cfg.Privacy.NoFingerprinting {
		count++
	}
	if cfg.Privacy.NoCrossSite {
		count++
	}
	if cfg.Privacy.NoProviderMeta {
		count++
	}
	if cfg.Privacy.NoKeystroke {
		count++
	}
	if cfg.Privacy.NoMouse {
		count++
	}
	if cfg.Privacy.NoSessionIDs {
		count++
	}
	if cfg.Privacy.NoIPAddresses {
		count++
	}
	if count != 12 {
		t.Errorf("Privacy non-negotiables count = %d, want 12", count)
	}
}
