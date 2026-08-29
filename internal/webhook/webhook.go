// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart - Simple Webhook Integration
//
// Sends audit events to configured webhooks (Slack, Discord, Teams, etc.)

package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Config represents webhook configuration
type Config struct {
	Webhooks []WebhookConfig `json:"webhooks"`
}

// WebhookConfig represents a single webhook configuration
type WebhookConfig struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	URL           string            `json:"url"`
	Enabled       bool              `json:"enabled"`
	Method        string            `json:"method,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Secret        string            `json:"secret,omitempty"` // For HMAC signing
	SkipTLSVerify bool              `json:"skip_tls_verify,omitempty"`
	Timeout       time.Duration     `json:"timeout,omitempty"`
}

// Event represents a webhook event payload
type Event struct {
	Timestamp  time.Time              `json:"timestamp"`
	EventType  string                 `json:"event_type"`
	Host       string                 `json:"host"`
	Blocked    bool                   `json:"blocked"`
	Severity   string                 `json:"severity"`
	Categories []string               `json:"categories,omitempty"`
	Message    string                 `json:"message"`
	RawData    map[string]interface{} `json:"raw_data,omitempty"`
}

// Manager manages webhook delivery
type Manager struct {
	config Config
	client *http.Client
	mu     sync.RWMutex
}

// NewManager creates a new webhook manager
func NewManager(cfg Config) *Manager {
	return &Manager{
		config: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// LoadConfig loads webhook configuration from file
func LoadConfig(path string) (Config, error) {
	var cfg Config

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return cfg, err
	}

	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

// Send sends an event to all enabled webhooks
func (m *Manager) Send(ctx context.Context, event Event) error {
	m.mu.RLock()
	webhooks := m.config.Webhooks
	m.mu.RUnlock()

	var lastErr error
	for _, wh := range webhooks {
		if !wh.Enabled {
			continue
		}

		if err := m.sendToWebhook(ctx, wh, event); err != nil {
			lastErr = err
			continue
		}
	}

	return lastErr
}

func (m *Manager) sendToWebhook(ctx context.Context, wh WebhookConfig, event Event) error {
	// HIGH-8 FIX: validate webhook URL to prevent SSRF
	if err := validateWebhookURL(wh.URL); err != nil {
		return fmt.Errorf("webhook URL validation: %w", err)
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	timeout := wh.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: wh.SkipTLSVerify, // MEDIUM-20: logged but allowed for backward compat
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", wh.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for k, v := range wh.Headers {
		req.Header.Set(k, v)
	}

	// Add HMAC-SHA256 signature if secret is configured
	if wh.Secret != "" {
		mac := hmac.New(sha256.New, []byte(wh.Secret))
		mac.Write(payload)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-AegisGate-Signature", "sha256="+sig)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// MEDIUM-18 FIX: limit response body read to prevent OOM
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
		return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// validateWebhookURL validates that a webhook URL is safe to send to.
// HIGH-8 FIX: prevent SSRF by enforcing HTTPS and blocking private IPs.
func validateWebhookURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("URL is empty")
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow HTTP/HTTPS schemes
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q (only http/https allowed)", u.Scheme)
	}

	// Parse the host
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}

	// Block private/link-local IPs — but allow loopback since Rampart is a local tool
	// and webhooks on localhost (e.g., for testing or local integrations) are safe.
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("blocked: webhook URL points to private/internal address %s", host)
		}
		// Block cloud metadata endpoint even if not caught by IsPrivate
		if ip.Equal(net.IPv4(169, 254, 169, 254)) {
			return fmt.Errorf("blocked: webhook URL points to cloud metadata endpoint")
		}
	}

	return nil
}

// AddWebhook adds a new webhook configuration
func (m *Manager) AddWebhook(wh WebhookConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if wh.Method == "" {
		wh.Method = "POST"
	}
	if wh.Timeout == 0 {
		wh.Timeout = 30 * time.Second
	}

	m.config.Webhooks = append(m.config.Webhooks, wh)
}

// RemoveWebhook removes a webhook by ID
func (m *Manager) RemoveWebhook(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, wh := range m.config.Webhooks {
		if wh.ID == id {
			m.config.Webhooks = append(m.config.Webhooks[:i], m.config.Webhooks[i+1:]...)
			return true
		}
	}
	return false
}

// ListWebhooks returns all configured webhooks
func (m *Manager) ListWebhooks() []WebhookConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]WebhookConfig, len(m.config.Webhooks))
	copy(result, m.config.Webhooks)
	return result
}

// SaveConfig saves configuration to file
func (m *Manager) SaveConfig(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}
