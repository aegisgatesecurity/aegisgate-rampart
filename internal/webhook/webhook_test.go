// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart - Webhook tests

package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNewManager verifies the constructor sets defaults correctly
func TestNewManager(t *testing.T) {
	cfg := Config{
		Webhooks: []WebhookConfig{
			{ID: "test1", Name: "Test", URL: "http://localhost:9999", Enabled: true},
		},
	}
	m := NewManager(cfg)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.client == nil {
		t.Fatal("client not initialized")
	}
	if len(m.config.Webhooks) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(m.config.Webhooks))
	}
	if m.config.Webhooks[0].ID != "test1" {
		t.Errorf("expected ID 'test1', got '%s'", m.config.Webhooks[0].ID)
	}
}

// TestLoadConfig tests loading webhook configuration from file
func TestLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "webhooks.json")

	cfgData := Config{
		Webhooks: []WebhookConfig{
			{ID: "wh1", Name: "Slack", URL: "http://slack.example.com/hook", Enabled: true},
			{ID: "wh2", Name: "Discord", URL: "http://discord.example.com/hook", Enabled: false},
		},
	}
	data, _ := json.MarshalIndent(cfgData, "", "  ")
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(loaded.Webhooks) != 2 {
		t.Fatalf("expected 2 webhooks, got %d", len(loaded.Webhooks))
	}
	if loaded.Webhooks[0].ID != "wh1" {
		t.Errorf("expected first webhook ID 'wh1', got '%s'", loaded.Webhooks[0].ID)
	}
	if !loaded.Webhooks[0].Enabled {
		t.Error("expected first webhook to be enabled")
	}
	if loaded.Webhooks[1].Enabled {
		t.Error("expected second webhook to be disabled")
	}
}

// TestLoadConfig_NonExistent returns empty config without error
func TestLoadConfig_NonExistent(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/webhooks.json")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if len(cfg.Webhooks) != 0 {
		t.Fatalf("expected 0 webhooks, got %d", len(cfg.Webhooks))
	}
}

// TestLoadConfig_InvalidJSON returns error for malformed JSON
func TestLoadConfig_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "webhooks.json")
	if err := os.WriteFile(cfgPath, []byte("{invalid json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// TestSend_Success sends an event to a mock webhook server
func TestSend_Success(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{
		Webhooks: []WebhookConfig{
			{ID: "test", Name: "Test", URL: server.URL, Enabled: true},
		},
	}
	m := NewManager(cfg)

	event := Event{
		EventType: "test_event",
		Host:      "localhost",
		Blocked:   true,
		Severity:  "high",
		Message:   "Test alert",
	}
	if err := m.Send(context.Background(), event); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var received Event
	if err := json.Unmarshal(receivedBody, &received); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if received.EventType != "test_event" {
		t.Errorf("expected event_type 'test_event', got '%s'", received.EventType)
	}
	if !received.Blocked {
		t.Error("expected blocked=true")
	}
}

// TestSend_DisabledWebhook skips disabled webhooks
func TestSend_DisabledWebhook(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{
		Webhooks: []WebhookConfig{
			{ID: "disabled", Name: "Disabled", URL: server.URL, Enabled: false},
		},
	}
	m := NewManager(cfg)
	if err := m.Send(context.Background(), Event{EventType: "test"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if called {
		t.Error("disabled webhook was called")
	}
}

// TestSend_HTTPError returns error on non-2xx response
func TestSend_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	cfg := Config{
		Webhooks: []WebhookConfig{
			{ID: "err", Name: "Error", URL: server.URL, Enabled: true},
		},
	}
	m := NewManager(cfg)
	err := m.Send(context.Background(), Event{EventType: "test"})
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

// TestSend_CustomHeaders verifies custom headers are sent
func TestSend_CustomHeaders(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{
		Webhooks: []WebhookConfig{
			{ID: "auth", Name: "Auth", URL: server.URL, Enabled: true,
				Headers: map[string]string{"Authorization": "Bearer secret123"}},
		},
	}
	m := NewManager(cfg)
	if err := m.Send(context.Background(), Event{EventType: "test"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if receivedAuth != "Bearer secret123" {
		t.Errorf("expected Authorization header 'Bearer secret123', got '%s'", receivedAuth)
	}
}

// TestSend_ConnectionError returns error on connection failure
func TestSend_ConnectionError(t *testing.T) {
	cfg := Config{
		Webhooks: []WebhookConfig{
			{ID: "dead", Name: "Dead", URL: "http://127.0.0.1:0/hook", Enabled: true, Timeout: 1 * time.Second},
		},
	}
	m := NewManager(cfg)
	err := m.Send(context.Background(), Event{EventType: "test"})
	if err == nil {
		t.Fatal("expected error for connection failure, got nil")
	}
}

// TestAddWebhook adds a webhook and verifies defaults
func TestAddWebhook(t *testing.T) {
	m := NewManager(Config{})
	wh := WebhookConfig{ID: "new", Name: "New", URL: "http://example.com", Enabled: true}
	m.AddWebhook(wh)
	if len(m.config.Webhooks) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(m.config.Webhooks))
	}
	if m.config.Webhooks[0].Method != "POST" {
		t.Errorf("expected default Method 'POST', got '%s'", m.config.Webhooks[0].Method)
	}
	if m.config.Webhooks[0].Timeout != 30*time.Second {
		t.Errorf("expected default Timeout 30s, got %v", m.config.Webhooks[0].Timeout)
	}
}

// TestRemoveWebhook removes a webhook by ID
func TestRemoveWebhook(t *testing.T) {
	cfg := Config{
		Webhooks: []WebhookConfig{
			{ID: "keep", Name: "Keep", URL: "http://a.com", Enabled: true},
			{ID: "remove", Name: "Remove", URL: "http://b.com", Enabled: true},
		},
	}
	m := NewManager(cfg)
	if !m.RemoveWebhook("remove") {
		t.Fatal("expected RemoveWebhook to return true")
	}
	if len(m.config.Webhooks) != 1 {
		t.Fatalf("expected 1 webhook after removal, got %d", len(m.config.Webhooks))
	}
	if m.config.Webhooks[0].ID != "keep" {
		t.Errorf("expected remaining webhook ID 'keep', got '%s'", m.config.Webhooks[0].ID)
	}
}

// TestRemoveWebhook_NotFound returns false for unknown ID
func TestRemoveWebhook_NotFound(t *testing.T) {
	m := NewManager(Config{
		Webhooks: []WebhookConfig{{ID: "exists", Name: "Exists", URL: "http://a.com", Enabled: true}},
	})
	if m.RemoveWebhook("nonexistent") {
		t.Fatal("expected RemoveWebhook to return false for unknown ID")
	}
}

// TestListWebhooks returns a copy of webhooks
func TestListWebhooks(t *testing.T) {
	cfg := Config{
		Webhooks: []WebhookConfig{
			{ID: "a", Name: "A", URL: "http://a.com", Enabled: true},
			{ID: "b", Name: "B", URL: "http://b.com", Enabled: false},
		},
	}
	m := NewManager(cfg)
	list := m.ListWebhooks()
	if len(list) != 2 {
		t.Fatalf("expected 2 webhooks, got %d", len(list))
	}
	// Verify it's a copy
	list[0].ID = "modified"
	if m.config.Webhooks[0].ID != "a" {
		t.Error("modifying returned list affected internal state")
	}
}

// TestSaveConfig saves configuration to file
func TestSaveConfig(t *testing.T) {
	m := NewManager(Config{
		Webhooks: []WebhookConfig{
			{ID: "save", Name: "Save", URL: "http://save.com", Enabled: true},
		},
	})
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "saved.json")
	if err := m.SaveConfig(cfgPath); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("saved file not found: %v", err)
	}
	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(loaded.Webhooks) != 1 {
		t.Fatalf("expected 1 webhook in loaded config, got %d", len(loaded.Webhooks))
	}
	if loaded.Webhooks[0].ID != "save" {
		t.Errorf("expected ID 'save', got '%s'", loaded.Webhooks[0].ID)
	}
}

// TestSend_MultipleWebhooks sends to all enabled webhooks
func TestSend_MultipleWebhooks(t *testing.T) {
	count1 := 0
	count2 := 0
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count1++
		w.WriteHeader(http.StatusOK)
	}))
	defer server1.Close()
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count2++
		w.WriteHeader(http.StatusOK)
	}))
	defer server2.Close()

	cfg := Config{
		Webhooks: []WebhookConfig{
			{ID: "s1", Name: "S1", URL: server1.URL, Enabled: true},
			{ID: "s2", Name: "S2", URL: server2.URL, Enabled: true},
			{ID: "s3", Name: "S3", URL: server1.URL, Enabled: false},
		},
	}
	m := NewManager(cfg)
	if err := m.Send(context.Background(), Event{EventType: "multi"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if count1 != 1 {
		t.Errorf("expected server1 called 1 time, got %d", count1)
	}
	if count2 != 1 {
		t.Errorf("expected server2 called 1 time, got %d", count2)
	}
}
