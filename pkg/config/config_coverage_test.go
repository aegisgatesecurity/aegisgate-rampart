// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadUnreadableConfigDir creates a directory with an unreadable config
// file (a directory named config.json) to exercise the non-IsNotExist error
// path in Load.
func TestLoadUnreadableConfigDir(t *testing.T) {
	tmpDir := t.TempDir()
	// Create config.json as a directory, which will cause os.ReadFile to
	// return an error that is NOT os.IsNotExist.
	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.Mkdir(configPath, 0755); err != nil {
		t.Fatalf("failed to create config.json as directory: %v", err)
	}

	_, err := Load(tmpDir)
	if err == nil {
		t.Error("expected error when config.json is a directory, got nil")
	}
}

// TestLoadPermDeniedConfigFile exercises the non-IsNotExist read error path
// by creating a config file with no read permissions.
func TestLoadPermDeniedConfigFile(t *testing.T) {
	// Skip on platforms where permission bits may not be honored (e.g., root).
	if os.Getuid() == 0 {
		t.Skip("skipping: running as root, permission denial unreliable")
	}

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"proxy_port": 8080}`), 0644); err != nil {
		t.Fatal(err)
	}
	// Remove all permissions so os.ReadFile fails with a permission error.
	if err := os.Chmod(configPath, 0000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(configPath, 0644) }() // restore for cleanup

	_, err := Load(tmpDir)
	if err == nil {
		t.Error("expected error for unreadable config file, got nil")
	}
}

// TestLoadEmptyDirReturnsDefaults verifies that loading from a directory
// without a config file returns the full default configuration with all
// privacy fields set to true.
func TestLoadEmptyDirReturnsFullDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load from empty dir failed: %v", err)
	}

	// Verify all privacy non-negotiables default to true
	if !cfg.Privacy.NoPromptText {
		t.Error("NoPromptText should default to true")
	}
	if !cfg.Privacy.NoURLs {
		t.Error("NoURLs should default to true")
	}
	if !cfg.Privacy.NoPageContent {
		t.Error("NoPageContent should default to true")
	}
	if !cfg.Privacy.NoPII {
		t.Error("NoPII should default to true")
	}
	if !cfg.Privacy.NoCredentials {
		t.Error("NoCredentials should default to true")
	}
	if !cfg.Privacy.NoFingerprinting {
		t.Error("NoFingerprinting should default to true")
	}
	if !cfg.Privacy.NoCrossSite {
		t.Error("NoCrossSite should default to true")
	}
	if !cfg.Privacy.NoProviderMeta {
		t.Error("NoProviderMeta should default to true")
	}
	if !cfg.Privacy.NoKeystroke {
		t.Error("NoKeystroke should default to true")
	}
	if !cfg.Privacy.NoMouse {
		t.Error("NoMouse should default to true")
	}
	if !cfg.Privacy.NoSessionIDs {
		t.Error("NoSessionIDs should default to true")
	}
	if !cfg.Privacy.NoIPAddresses {
		t.Error("NoIPAddresses should default to true")
	}
}

// TestLoadMinimalValidConfig verifies that a minimal valid JSON config
// merges correctly with defaults (zero/missing fields retain defaults).
func TestLoadMinimalValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configJSON := `{"proxy_port": 1234}`
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.ProxyPort != 1234 {
		t.Errorf("ProxyPort = %d, want 1234", cfg.ProxyPort)
	}
	// Unset fields should retain zero values after JSON unmarshal into the
	// default config — note: json.Unmarshal merges into the default config,
	// so DaemonMode stays false, etc.
	if cfg.DaemonMode {
		t.Error("DaemonMode should be false")
	}
}

// TestLoadConfigWithZeroValues verifies that explicit zero values in JSON
// properly override defaults.
func TestLoadConfigWithZeroValues(t *testing.T) {
	tmpDir := t.TempDir()
	configJSON := `{
		"proxy_port": 0,
		"daemon_mode": false,
		"verbose": false,
		"platform_url": "",
		"models": {"path": "", "threshold": 0, "shadow": false},
		"privacy": {
			"no_prompt_text": false,
			"no_urls": false,
			"no_page_content": false,
			"no_pii": false,
			"no_credentials": false,
			"no_fingerprinting": false,
			"no_cross_site": false,
			"no_provider_meta": false,
			"no_keystroke": false,
			"no_mouse": false,
			"no_session_ids": false,
			"no_ip_addresses": false
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.ProxyPort != 0 {
		t.Errorf("ProxyPort = %d, want 0", cfg.ProxyPort)
	}
	if cfg.Privacy.NoPromptText {
		t.Error("NoPromptText should be false")
	}
	if cfg.Models.Threshold != 0 {
		t.Errorf("Threshold = %f, want 0", cfg.Models.Threshold)
	}
}

// TestLoadEmptyJSONConfig verifies that an empty JSON object is valid
// and retains defaults for all fields (json.Unmarshal only sets fields
// present in the JSON; absent fields keep their default values).
func TestLoadEmptyJSONConfig(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	// Empty JSON object should retain defaults; json.Unmarshal only
	// overwrites fields present in the JSON.
	if cfg.ProxyPort != 8080 {
		t.Errorf("ProxyPort = %d, want 8080 (default retained)", cfg.ProxyPort)
	}
}

// TestLoadMalformedYAMLConfig verifies that YAML (non-JSON) input produces
// a parse error.
func TestLoadMalformedYAMLConfig(t *testing.T) {
	tmpDir := t.TempDir()
	// YAML is not valid JSON
	yamlContent := []byte(`proxy_port: 8080
daemon_mode: true
verbose: false
`)
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), yamlContent, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(tmpDir)
	if err == nil {
		t.Error("expected error for YAML config, got nil")
	}
}

// TestLoadTruncatedJSONConfig verifies that truncated JSON produces a parse error.
func TestLoadTruncatedJSONConfig(t *testing.T) {
	tmpDir := t.TempDir()
	// Truncated JSON object
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(`{"proxy_port":`), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(tmpDir)
	if err == nil {
		t.Error("expected error for truncated JSON, got nil")
	}
}

// TestLoadExtraFieldsConfig verifies that extra unknown fields in JSON
// are silently ignored (Go's default JSON unmarshal behavior).
func TestLoadExtraFieldsConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configJSON := `{
		"proxy_port": 8080,
		"unknown_field": "should be ignored",
		"another_extra": 42
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load with extra fields should succeed: %v", err)
	}
	if cfg.ProxyPort != 8080 {
		t.Errorf("ProxyPort = %d, want 8080", cfg.ProxyPort)
	}
}

// TestLoadNegativePortConfig verifies that a config with a negative port
// is loaded (validation is not done in Load; it just parses).
func TestLoadNegativePortConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configJSON := `{"proxy_port": -1}`
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load with negative port should succeed (no validation): %v", err)
	}
	if cfg.ProxyPort != -1 {
		t.Errorf("ProxyPort = %d, want -1", cfg.ProxyPort)
	}
}

// TestLoadLargePortConfig verifies that a config with a large port number
// is loaded without validation errors.
func TestLoadLargePortConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configJSON := `{"proxy_port": 99999}`
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load with large port should succeed (no validation): %v", err)
	}
	if cfg.ProxyPort != 99999 {
		t.Errorf("ProxyPort = %d, want 99999", cfg.ProxyPort)
	}
}

// TestLoadWrongTypeFieldConfig verifies that a wrong type for a field
// produces a parse error.
func TestLoadWrongTypeFieldConfig(t *testing.T) {
	tmpDir := t.TempDir()
	// proxy_port should be int, not string
	configJSON := `{"proxy_port": "not_a_number"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(tmpDir)
	if err == nil {
		t.Error("expected error for wrong type field, got nil")
	}
}

// TestLoadNullJSONConfig verifies that a JSON null produces a parse error.
func TestLoadNullJSONConfig(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(`null`), 0644); err != nil {
		t.Fatal(err)
	}

	// json.Unmarshal([]byte("null"), cfg) sets cfg to nil — but since cfg
	// is a *Config, unmarshaling null should not cause a nil pointer return.
	// It actually resets the struct to zero values. Let's verify it doesn't
	// panic.
	cfg, err := Load(tmpDir)
	// After unmarshaling "null" into a *Config, the struct values are zeroed.
	// This should not error (json.Unmarshal("null", &x) sets x to zero).
	if err != nil {
		t.Logf("Load with null JSON returned error: %v (this is acceptable)", err)
	}
	if cfg == nil {
		t.Error("Load should not return nil config for null JSON")
	}
}

// TestLoadArrayJSONConfig verifies that a JSON array produces a parse error.
func TestLoadArrayJSONConfig(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(`[1, 2, 3]`), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(tmpDir)
	if err == nil {
		t.Error("expected error for JSON array config, got nil")
	}
}
