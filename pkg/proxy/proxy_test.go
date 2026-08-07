package proxy

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"
)

func TestIsTargetDomain(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	tests := []struct {
		host     string
		expected bool
	}{
		{"api.openai.com", true},
		{"chat.openai.com", true},
		{"api.anthropic.com", true},
		{"claude.ai", true},
		{"api.deepseek.com", true},
		{"chat.deepseek.com", true},
		{"www.google.com", false},
		{"github.com", false},
		{"localhost", false},
		{"", false},
	}

	for _, tt := range tests {
		result := p.isTargetDomain(tt.host)
		if result != tt.expected {
			t.Errorf("isTargetDomain(%q) = %v, want %v", tt.host, result, tt.expected)
		}
	}
}

func TestProxyNew(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ProxyPort = 0 // Let OS pick
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if p == nil {
		t.Fatal("New returned nil proxy")
	}
	if p.detector == nil {
		t.Error("Proxy should have a detector")
	}
	if len(p.targets) != 27 {
		t.Errorf("Proxy targets = %d, want 27", len(p.targets))
	}
}

func TestProxyNewWithConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Verbose = true
	cfg.DaemonMode = true
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New with config failed: %v", err)
	}
	_ = p
}

func TestGetStats(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	stats := p.GetStats()
	if stats.TotalRequests != 0 {
		t.Errorf("Initial TotalRequests = %d, want 0", stats.TotalRequests)
	}
	if stats.Detections != 0 {
		t.Errorf("Initial Detections = %d, want 0", stats.Detections)
	}
	if stats.BlockedRequests != 0 {
		t.Errorf("Initial BlockedRequests = %d, want 0", stats.BlockedRequests)
	}
}

func TestProxyStatsStruct(t *testing.T) {
	s := ProxyStats{
		TotalRequests:   100,
		Detections:      15,
		BlockedRequests: 2,
		MLDetections:    3,
		Intercepted:     50,
		PassedThrough:   50,
	}
	if s.TotalRequests != 100 {
		t.Errorf("TotalRequests = %d", s.TotalRequests)
	}
	if s.Detections != 15 {
		t.Errorf("Detections = %d", s.Detections)
	}
	if s.BlockedRequests != 2 {
		t.Errorf("BlockedRequests = %d", s.BlockedRequests)
	}
	if s.MLDetections != 3 {
		t.Errorf("MLDetections = %d", s.MLDetections)
	}
	if s.Intercepted != 50 {
		t.Errorf("Intercepted = %d", s.Intercepted)
	}
	if s.PassedThrough != 50 {
		t.Errorf("PassedThrough = %d", s.PassedThrough)
	}
}

func TestNotifyDesktop(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	// notifyDesktop should not panic — pass a valid summary
	summary := &detector.Summary{
		TotalDetections: 1,
		Results:         []detector.Result{{Category: "pii", Severity: "high", Text: "SSN"}},
	}
	p.notifyDesktop("request", "api.openai.com", summary)
}

func TestAll27TargetDomainsPresent(t *testing.T) {
	cfg := config.DefaultConfig()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	expectedDomains := []string{
		"api.openai.com", "chat.openai.com", "chatgpt.com",
		"api.anthropic.com", "claude.ai",
		"generativelanguage.googleapis.com", "gemini.google.com",
		"api.copilot.microsoft.com", "copilot.microsoft.com", "copilot.cloud.microsoft",
		"api.perplexity.ai", "perplexity.ai", "www.perplexity.ai",
		"api.x.ai", "grok.com", "www.grok.com",
		"api.mistral.ai", "codestral.mistral.ai", "chat.mistral.ai", "le-chat.mistral.ai",
		"api.deepseek.com", "chat.deepseek.com",
		"api.duck.ai", "duck.ai", "www.duck.ai",
		"meta.ai", "www.meta.ai",
	}

	for _, domain := range expectedDomains {
		if !p.isTargetDomain(domain) {
			t.Errorf("Expected target domain %s not found", domain)
		}
	}
}
