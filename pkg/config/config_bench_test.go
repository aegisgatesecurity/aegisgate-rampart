package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkConfig benchmarks config loading and parsing from a JSON file.
func BenchmarkConfig(b *testing.B) {
	// Build a realistic config JSON payload matching the production schema.
	cfg := &Config{
		ProxyPort:   8080,
		DaemonMode:  false,
		Verbose:     false,
		PlatformURL: "https://platform.aegisgate.dev",
		Targets:     DefaultTargets(),
		Models: ModelConfig{
			Path:      "/opt/aegisgate/models/threat-detection.onnx",
			Threshold: 0.05,
			Shadow:    true,
		},
		Privacy: PrivacyConfig{
			NoPromptText:     true,
			NoURLs:           true,
			NoPageContent:    true,
			NoPII:            true,
			NoCredentials:    true,
			NoFingerprinting: true,
			NoCrossSite:      true,
			NoProviderMeta:   true,
			NoKeystroke:      true,
			NoMouse:          true,
			NoSessionIDs:     true,
			NoIPAddresses:    true,
		},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		b.Fatalf("marshal config: %v", err)
	}

	// Create a temp directory with the config file.
	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		b.Fatalf("write config: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Load(tmpDir)
		if err != nil {
			b.Fatalf("Load failed: %v", err)
		}
	}
}

// BenchmarkConfigDefault benchmarks default config generation (no file I/O).
func BenchmarkConfigDefault(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DefaultConfig()
	}
}

// BenchmarkConfigJSONUnmarshal benchmarks JSON parsing of a config payload.
func BenchmarkConfigJSONUnmarshal(b *testing.B) {
	cfg := DefaultConfig()
	data, err := json.Marshal(cfg)
	if err != nil {
		b.Fatalf("marshal: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := &Config{}
		if err := json.Unmarshal(data, result); err != nil {
			b.Fatalf("unmarshal: %v", err)
		}
	}
}

// BenchmarkConfigTargets benchmarks building the default targets list.
func BenchmarkConfigTargets(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DefaultTargets()
	}
}

// BenchmarkConfigLargeFile benchmarks loading a large config file (stress test).
func BenchmarkConfigLargeFile(b *testing.B) {
	// Create a config with many target entries to stress parsing.
	targets := make([]TargetConfig, 200)
	for i := range targets {
		targets[i] = TargetConfig{
			Domain:      fmt.Sprintf("api%d.example.com", i),
			Paths:       []string{"/v1/chat/completions", "/v1/models", "/v1/embeddings"},
			Description: fmt.Sprintf("Test API %d", i),
		}
	}
	cfg := &Config{
		ProxyPort:   8080,
		DaemonMode:  false,
		Verbose:     false,
		PlatformURL: "https://platform.aegisgate.dev",
		Targets:     targets,
		Models: ModelConfig{
			Path:      "/opt/aegisgate/models/threat-detection.onnx",
			Threshold: 0.05,
			Shadow:    true,
		},
		Privacy: PrivacyConfig{
			NoPromptText:  true,
			NoURLs:        true,
			NoPageContent: true,
			NoPII:         true,
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		b.Fatalf("marshal: %v", err)
	}

	tmpDir := b.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		b.Fatalf("write: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Load(tmpDir)
		if err != nil {
			b.Fatalf("Load failed: %v", err)
		}
	}
}
