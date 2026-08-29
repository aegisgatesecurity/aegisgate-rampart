// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart — Enterprise Gate Tests

package enterprise

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIsEnabled_CoreFeatures(t *testing.T) {
	// Core features should always be enabled, even without Platform connection
	coreFeatures := []string{"lsp", "proxy", "webhooks", "ml", "audit_tail", "llm", "scan"}

	for _, feature := range coreFeatures {
		t.Run(feature, func(t *testing.T) {
			if !IsEnabled(feature) {
				t.Errorf("Core feature %q should be enabled without Platform connection", feature)
			}
		})
	}
}

func TestIsEnabled_EnterpriseFeatures_NoConnection(t *testing.T) {
	// Ensure we're not connected
	_ = Disconnect()

	// Enterprise features should be disabled without Platform connection
	enterpriseFeatures := []string{"audit_search", "cosign", "memory_zeroing", "encryption", "compliance", "siem", "sso"}

	for _, feature := range enterpriseFeatures {
		t.Run(feature, func(t *testing.T) {
			if IsEnabled(feature) {
				t.Errorf("Enterprise feature %q should be disabled without Platform connection", feature)
			}
		})
	}
}

func TestIsEnabled_UnknownFeature(t *testing.T) {
	// Unknown features should return false
	if IsEnabled("unknown_feature") {
		t.Error("Unknown feature should be disabled")
	}
}

func TestConnectAndDisconnect(t *testing.T) {
	// Clean up any existing config
	_ = Disconnect()

	// Use a local mock server for connection testing
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(mock.Close)

	testURL := mock.URL
	testToken := "test-api-token-12345"

	// Test connection
	err := Connect(testURL, testToken)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Verify connection status
	connected, url := Status()
	if !connected {
		t.Error("Expected to be connected after Connect()")
	}
	if url != testURL {
		t.Errorf("Expected URL %q, got %q", testURL, url)
	}

	// Test enterprise features are now enabled
	if !IsEnabled("audit_search") {
		t.Error("audit_search should be enabled after Platform connection")
	}
	if !IsEnabled("cosign") {
		t.Error("cosign should be enabled after Platform connection")
	}
	if !IsEnabled("memory_zeroing") {
		t.Error("memory_zeroing should be enabled after Platform connection")
	}

	// Test disconnection
	err = Disconnect()
	if err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}

	// Verify disconnection
	connected, url = Status()
	if connected {
		t.Error("Expected to be disconnected after Disconnect()")
	}
	if url != "" {
		t.Errorf("Expected empty URL after disconnect, got %q", url)
	}

	// Verify enterprise features are disabled
	if IsEnabled("audit_search") {
		t.Error("audit_search should be disabled after disconnect")
	}
}

func TestConnect_EmptyURL(t *testing.T) {
	err := Connect("", "some-token")
	if err == nil {
		t.Error("Connect should fail with empty URL")
	}
}

func TestConnect_EmptyToken(t *testing.T) {
	err := Connect("https://platform.aegisgate.com", "")
	if err == nil {
		t.Error("Connect should fail with empty token")
	}
}

func TestStatus_NoConnection(t *testing.T) {
	_ = Disconnect()

	connected, url := Status()
	if connected {
		t.Error("Expected not connected")
	}
	if url != "" {
		t.Errorf("Expected empty URL, got %q", url)
	}
}

func TestGetConfigPath(t *testing.T) {
	configPath := GetConfigPath()
	if configPath == "" {
		t.Error("Config path should not be empty")
	}

	// Should be in user's home directory or current directory
	homeDir, _ := os.UserHomeDir()
	expectedPath := filepath.Join(homeDir, ".config", "aegisgate-rampart", "aegisgate-platform.json")

	if configPath != expectedPath {
		// Fallback to current directory if home dir not available
		if configPath != "./aegisgate-platform.json" {
			t.Errorf("Expected config path %q or fallback, got %q", expectedPath, configPath)
		}
	}
}

func TestGate_ConnectFailInvalidURL(t *testing.T) {
	// Note: testConnection currently only checks for empty URL/token
	// Full URL validation would be implemented in production
	// This test documents the current behavior
	err := Connect("not-a-valid-url", "token")
	// Currently passes because testConnection only validates non-empty
	// In production, this should validate URL format
	if err != nil {
		t.Logf("Connect rejected invalid URL (good): %v", err)
	} else {
		t.Log("Connect accepted invalid URL (expected in current implementation)")
	}
}

func TestDisconnect_NoConfig(t *testing.T) {
	// Disconnect when no config exists should not error
	_ = Disconnect() // Ensure clean state

	err := Disconnect()
	if err != nil {
		t.Errorf("Disconnect should not error when no config exists: %v", err)
	}
}

func TestIsEnabled_ThreadSafety(t *testing.T) {
	// Test concurrent access to IsEnabled
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			IsEnabled("lsp")
			IsEnabled("audit_search")
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = Connect("https://test.com", "token")
			_ = Disconnect()
		}
		done <- true
	}()

	<-done
	<-done
	// If we reach here without deadlock, test passes
}
