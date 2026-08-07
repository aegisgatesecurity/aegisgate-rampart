package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

// BenchmarkProxy benchmarks proxy request handling via the /detect API endpoint.
// This exercises the full detection pipeline through the proxy's HTTP handler.
func BenchmarkProxy(b *testing.B) {
	cfg := &config.Config{
		ProxyPort:   0, // Not actually listening
		DaemonMode:  false,
		Verbose:     false,
		PlatformURL: "",
		Targets: []config.TargetConfig{
			{Domain: "api.openai.com", Paths: []string{"/v1/chat/completions"}, Description: "OpenAI API"},
		},
		Models: config.ModelConfig{
			Path:      "",
			Threshold: 0.7,
			Shadow:    true,
		},
		Privacy: config.PrivacyConfig{
			NoPromptText:  true,
			NoPII:         true,
			NoCredentials: true,
		},
	}

	p, err := New(cfg)
	if err != nil {
		b.Fatalf("New proxy: %v", err)
	}

	// Test payload: realistic AI prompt with PII.
	reqBody := map[string]string{
		"text": "What is the capital of France? Also, my SSN is 123-45-6789 and my email is user@example.com.",
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		b.Fatalf("marshal request: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/detect", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		p.HandleDetectAPI(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status: %d", w.Code)
		}
	}
}

// BenchmarkProxyClean benchmarks /detect with clean (non-malicious) text.
func BenchmarkProxyClean(b *testing.B) {
	cfg := &config.Config{
		ProxyPort:   0,
		DaemonMode:  false,
		Verbose:     false,
		PlatformURL: "",
		Targets: []config.TargetConfig{
			{Domain: "api.openai.com", Paths: []string{"/v1/chat/completions"}, Description: "OpenAI API"},
		},
		Models: config.ModelConfig{
			Path:      "",
			Threshold: 0.7,
			Shadow:    true,
		},
		Privacy: config.PrivacyConfig{
			NoPromptText:  true,
			NoPII:         true,
			NoCredentials: true,
		},
	}

	p, err := New(cfg)
	if err != nil {
		b.Fatalf("New proxy: %v", err)
	}

	reqBody := map[string]string{
		"text": "What is the capital of France?",
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		b.Fatalf("marshal request: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/detect", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		p.HandleDetectAPI(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status: %d", w.Code)
		}
	}
}

// BenchmarkProxyStats benchmarks the /stats API endpoint.
func BenchmarkProxyStats(b *testing.B) {
	cfg := &config.Config{
		ProxyPort:  0,
		DaemonMode: false,
		Targets:    []config.TargetConfig{},
		Models: config.ModelConfig{
			Path:      "",
			Threshold: 0.7,
			Shadow:    true,
		},
		Privacy: config.PrivacyConfig{
			NoPromptText: true,
		},
	}

	p, err := New(cfg)
	if err != nil {
		b.Fatalf("New proxy: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/stats", nil)
		w := httptest.NewRecorder()
		p.HandleStatsAPI(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status: %d", w.Code)
		}
	}
}

// BenchmarkProxyDetectLarge benchmarks /detect with a large input payload.
func BenchmarkProxyDetectLarge(b *testing.B) {
	cfg := &config.Config{
		ProxyPort:  0,
		DaemonMode: false,
		Targets: []config.TargetConfig{
			{Domain: "api.openai.com", Paths: []string{"/v1/chat/completions"}, Description: "OpenAI API"},
		},
		Models: config.ModelConfig{
			Path:      "",
			Threshold: 0.7,
			Shadow:    true,
		},
		Privacy: config.PrivacyConfig{
			NoPromptText:  true,
			NoPII:         true,
			NoCredentials: true,
		},
	}

	p, err := New(cfg)
	if err != nil {
		b.Fatalf("New proxy: %v", err)
	}

	// Build a large text payload (~10KB)
	longText := "This is a normal sentence about software development. "
	for len(longText) < 10*1024 {
		longText += "The quick brown fox jumps over the lazy dog. "
	}
	longText += " Contact: admin@evil.com with secret AKIAIOSFODNN7EXAMPLE."

	reqBody := map[string]string{"text": longText}
	body, err := json.Marshal(reqBody)
	if err != nil {
		b.Fatalf("marshal request: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/detect", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		p.HandleDetectAPI(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status: %d", w.Code)
		}
	}
}
