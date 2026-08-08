package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/platform"
)

// Operating mode for Rampart: monitor-only or active blocking.
const (
	ModeMonitor = "monitor" // Log detections but allow all traffic
	ModeBlock   = "block"   // Actively block requests that match criteria
)

// BlockSeverityThreshold defines which severity levels trigger blocking.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Config holds all Rampart configuration.
type Config struct {
	ProxyPort       int            `json:"proxy_port"`
	DaemonMode      bool           `json:"daemon_mode"`
	Verbose         bool           `json:"verbose"`
	PlatformURL     string         `json:"platform_url"`
	PlatformKey     string         `json:"platform_api_key"`
	RateLimitRPS    int            `json:"rate_limit_rps"`
	Mode            string         `json:"mode"` // "monitor" (default) or "block"
	Block           BlockConfig    `json:"block"`
	Targets         []TargetConfig `json:"targets"`
	Models          ModelConfig    `json:"models"`
	Privacy         PrivacyConfig  `json:"privacy"`
	PprofAddr       string         `json:"pprof_addr"`        // pprof debug server address (e.g., "localhost:6060"), empty = disabled
	CAKeyPassphrase string         `json:"ca_key_passphrase"` // passphrase for CA key encryption at rest (empty = unencrypted)
}

// BlockConfig defines what gets blocked and how.
// Only used when Mode is "block".
type BlockConfig struct {
	// Threshold is the minimum severity to block on.
	// Options: "low", "medium", "high", "critical"
	// Default: "high" — blocks on high and critical findings.
	Threshold string `json:"threshold"`

	// Categories is the list of detection categories to block on.
	// Empty means block on ALL categories.
	// Options: "pii", "secrets", "xss", "toxicity", "compliance", "ml_threat"
	Categories []string `json:"categories"`

	// StatusCode is the HTTP status code returned when blocking.
	// Default: 403 (Forbidden)
	StatusCode int `json:"status_code"`

	// IncludeDetections controls whether the block response includes
	// the list of specific detections. Default: true (transparency).
	IncludeDetections bool `json:"include_detections"`

	// Message is the custom message returned in the block response.
	// Default: "Request blocked by AegisGate Rampart"
	Message string `json:"message"`

	// BlockResponse controls whether Rampart blocks the outbound request
	// (user → AI), the inbound response (AI → user), or both.
	// Options: "both", "request", "response"
	// Default: "both"
	BlockResponse string `json:"block_response"`
}

// TargetConfig defines an AI API endpoint to intercept.
type TargetConfig struct {
	Domain      string   `json:"domain"`
	Paths       []string `json:"paths"`
	Description string   `json:"description"`
}

// ModelConfig defines the ML model configuration.
type ModelConfig struct {
	Path      string  `json:"path"`
	Threshold float64 `json:"threshold"`
	Shadow    bool    `json:"shadow"`
}

// PrivacyConfig enforces the 12 non-negotiables.
type PrivacyConfig struct {
	NoPromptText     bool `json:"no_prompt_text"`
	NoURLs           bool `json:"no_urls"`
	NoPageContent    bool `json:"no_page_content"`
	NoPII            bool `json:"no_pii"`
	NoCredentials    bool `json:"no_credentials"`
	NoFingerprinting bool `json:"no_fingerprinting"`
	NoCrossSite      bool `json:"no_cross_site"`
	NoProviderMeta   bool `json:"no_provider_meta"`
	NoKeystroke      bool `json:"no_keystroke"`
	NoMouse          bool `json:"no_mouse"`
	NoSessionIDs     bool `json:"no_session_ids"`
	NoIPAddresses    bool `json:"no_ip_addresses"`
}

// DefaultConfig returns the production default configuration.
func DefaultConfig() *Config {
	return &Config{
		ProxyPort:   8080,
		DaemonMode:  false,
		Verbose:     false,
		PlatformURL: "",
		Mode:        ModeMonitor,
		Targets:     DefaultTargets(),
		Models: ModelConfig{
			Path:      "/opt/aegisgate/models/threat-detection.onnx",
			Threshold: 0.05,
			Shadow:    true,
		},
		Block: BlockConfig{
			Threshold:         SeverityHigh,
			Categories:        []string{}, // empty = all categories
			StatusCode:        403,
			IncludeDetections: true,
			Message:           "Request blocked by AegisGate Rampart",
			BlockResponse:     "both",
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
}

// DefaultTargets returns the AI API endpoints and web surfaces Rampart intercepts.
// Aligned with Lens v0.3.0 providers — covers the same 10 providers,
// but Rampart intercepts BOTH API endpoints (for API clients) and
// web surfaces (for desktop apps and browser traffic).
func DefaultTargets() []TargetConfig {
	return []TargetConfig{
		// OpenAI / ChatGPT
		{Domain: "api.openai.com", Paths: []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/audio/*", "/v1/images/*", "/v1/models"}, Description: "OpenAI API"},
		{Domain: "chat.openai.com", Paths: []string{"/api/*"}, Description: "ChatGPT Web"},
		{Domain: "chatgpt.com", Paths: []string{"/api/*"}, Description: "ChatGPT Web (alt)"},
		// Anthropic / Claude
		{Domain: "api.anthropic.com", Paths: []string{"/v1/messages", "/v1/complete"}, Description: "Anthropic API"},
		{Domain: "claude.ai", Paths: []string{"/api/*"}, Description: "Claude Web"},
		// Google Gemini
		{Domain: "generativelanguage.googleapis.com", Paths: []string{"/v1/*"}, Description: "Google Gemini API"},
		{Domain: "gemini.google.com", Paths: []string{"/api/*"}, Description: "Gemini Web"},
		// Microsoft Copilot
		{Domain: "api.copilot.microsoft.com", Paths: []string{"/v1/*"}, Description: "Microsoft Copilot API"},
		{Domain: "copilot.microsoft.com", Paths: []string{"/api/*"}, Description: "Copilot Web"},
		{Domain: "copilot.cloud.microsoft", Paths: []string{"/api/*"}, Description: "Copilot Web (alt)"},
		// Perplexity
		{Domain: "api.perplexity.ai", Paths: []string{"/chat/completions"}, Description: "Perplexity API"},
		{Domain: "perplexity.ai", Paths: []string{"/api/*"}, Description: "Perplexity Web"},
		{Domain: "www.perplexity.ai", Paths: []string{"/api/*"}, Description: "Perplexity Web (alt)"},
		// Grok
		{Domain: "api.x.ai", Paths: []string{"/v1/chat/completions"}, Description: "Grok API"},
		{Domain: "grok.com", Paths: []string{"/api/*"}, Description: "Grok Web"},
		{Domain: "www.grok.com", Paths: []string{"/api/*"}, Description: "Grok Web (alt)"},
		// Mistral
		{Domain: "codestral.mistral.ai", Paths: []string{"/v1/chat/completions", "/v1/fim/completions"}, Description: "Mistral Codestral API"},
		{Domain: "api.mistral.ai", Paths: []string{"/v1/chat/completions", "/v1/embeddings", "/v1/models"}, Description: "Mistral API"},
		{Domain: "chat.mistral.ai", Paths: []string{"/api/*"}, Description: "Mistral Le Chat Web"},
		{Domain: "le-chat.mistral.ai", Paths: []string{"/api/*"}, Description: "Mistral Le Chat Web (alt)"},
		// DeepSeek
		{Domain: "api.deepseek.com", Paths: []string{"/v1/chat/completions"}, Description: "DeepSeek API"},
		{Domain: "chat.deepseek.com", Paths: []string{"/api/*"}, Description: "DeepSeek Web"},
		// Duck.ai
		{Domain: "api.duck.ai", Paths: []string{"/v1/chat/completions"}, Description: "Duck.ai API"},
		{Domain: "duck.ai", Paths: []string{"/api/*"}, Description: "Duck.ai Web"},
		{Domain: "www.duck.ai", Paths: []string{"/api/*"}, Description: "Duck.ai Web (alt)"},
		// Meta AI
		{Domain: "meta.ai", Paths: []string{"/api/*"}, Description: "Meta AI Web"},
		{Domain: "www.meta.ai", Paths: []string{"/api/*"}, Description: "Meta AI Web (alt)"},
	}
}

// ConfigPath returns the default path to the configuration file.
func ConfigPath() string {
	return filepath.Join(platform.ConfigDir(), "config.json")
}

// Load reads configuration from the given directory, falling back to defaults.
func Load(dir string) (*Config, error) {
	cfg := DefaultConfig()

	if dir == "" {
		dir = platform.ConfigDir()
	}

	configPath := filepath.Join(dir, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}
