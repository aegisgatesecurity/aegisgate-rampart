// SPDX-License-Identifier: Apache-2.0
// Test coverage for enterprise Gate loadConfig

package enterprise

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Test with non-existent config file (should not error)
	tmpDir := t.TempDir()
	g := &Gate{
		configPath: filepath.Join(tmpDir, "nonexistent.json"),
	}
	err := g.loadConfig()
	if err != nil {
		t.Errorf("loadConfig with non-existent file should not error: %v", err)
	}

	// Test with valid config file
	configPath := filepath.Join(tmpDir, "platform.json")
	configData := `{"url":"https://platform.example.com","api_token":"test-token-123"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	g2 := &Gate{
		configPath: configPath,
	}
	err = g2.loadConfig()
	if err != nil {
		t.Errorf("loadConfig with valid config failed: %v", err)
	}
	if g2.platformURL != "https://platform.example.com" {
		t.Errorf("platformURL = %q, want %q", g2.platformURL, "https://platform.example.com")
	}
	if g2.apiToken != "test-token-123" {
		t.Errorf("apiToken = %q, want %q", g2.apiToken, "test-token-123")
	}
	if g2.isConnected {
		t.Error("isConnected should be false after loadConfig (requires explicit Connect)")
	}

	// Test with invalid JSON
	badConfigPath := filepath.Join(tmpDir, "bad.json")
	if err := os.WriteFile(badConfigPath, []byte("{invalid json}"), 0600); err != nil {
		t.Fatalf("write bad config: %v", err)
	}
	g3 := &Gate{
		configPath: badConfigPath,
	}
	err = g3.loadConfig()
	if err == nil {
		t.Error("loadConfig with invalid JSON should error")
	}
}
