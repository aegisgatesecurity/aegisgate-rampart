// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart — Enterprise Feature Gating
//
// Gates enterprise features behind Platform connection.
// Free users get core power-user features.
// Platform users get enterprise capabilities.

package enterprise

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Gate controls access to enterprise features.
type Gate struct {
	mu           sync.RWMutex
	platformURL  string
	apiToken     string
	isConnected  bool
	configPath   string
}

// Global gate instance.
var defaultGate *Gate

func init() {
	defaultGate = &Gate{
		configPath: getConfigPath(),
	}
	// Load existing connection config
	_ = defaultGate.loadConfig()
}

// PlatformConfig holds Platform connection settings.
type PlatformConfig struct {
	URL      string `json:"url"`
	APIToken string `json:"api_token"`
}

// IsEnabled checks if an enterprise feature is available.
func IsEnabled(feature string) bool {
	return defaultGate.IsEnabled(feature)
}

// IsEnabled checks if an enterprise feature is available.
func (g *Gate) IsEnabled(feature string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Core features always enabled
	coreFeatures := map[string]bool{
		"lsp":       true,
		"proxy":     true,
		"webhooks":  true,
		"ml":        true,
		"audit_tail": true,
		"llm":       true,
		"scan":      true,
	}

	if coreFeatures[feature] {
		return true
	}

	// Enterprise features require Platform connection
	if !g.isConnected {
		return false
	}

	// Connected to Platform, enterprise features enabled
	enterpriseFeatures := map[string]bool{
		"audit_search":   true,
		"cosign":         true,
		"memory_zeroing": true,
		"encryption":     true,
		"compliance":     true,
		"siem":           true,
		"sso":            true,
	}

	return enterpriseFeatures[feature]
}

// Connect establishes connection to Platform.
func Connect(url, token string) error {
	return defaultGate.Connect(url, token)
}

// Connect establishes connection to Platform.
func (g *Gate) Connect(url, token string) error {
	// Test connection first
	if err := testConnection(url, token); err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	g.platformURL = url
	g.apiToken = token
	g.isConnected = true

	// Save config
	return g.saveConfig()
}

// Disconnect removes Platform connection.
func Disconnect() error {
	return defaultGate.Disconnect()
}

// Disconnect removes Platform connection.
func (g *Gate) Disconnect() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.platformURL = ""
	g.apiToken = ""
	g.isConnected = false

	// Remove config
	if err := os.Remove(g.configPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// Status returns connection status.
func Status() (bool, string) {
	return defaultGate.Status()
}

// Status returns connection status.
func (g *Gate) Status() (bool, string) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if g.isConnected {
		return true, g.platformURL
	}
	return false, ""
}

// GetConfigPath returns the config file path.
func GetConfigPath() string {
	return defaultGate.configPath
}

func (g *Gate) loadConfig() error {
	data, err := os.ReadFile(g.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No config yet, not connected
		}
		return err
	}

	var cfg PlatformConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}

	g.platformURL = cfg.URL
	g.apiToken = cfg.APIToken
	g.isConnected = cfg.URL != "" && cfg.APIToken != ""

	return nil
}

func (g *Gate) saveConfig() error {
	cfg := PlatformConfig{
		URL:      g.platformURL,
		APIToken: g.apiToken,
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(g.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(g.configPath, data, 0600)
}

func getConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "./aegisgate-platform.json"
	}
	return filepath.Join(homeDir, ".config", "aegisgate-rampart", "aegisgate-platform.json")
}

func testConnection(url, token string) error {
	// TODO: Actually test Platform API connection
	// For now, just validate format
	if url == "" {
		return fmt.Errorf("URL is required")
	}
	if token == "" {
		return fmt.Errorf("API token is required")
	}
	return nil
}
