// SPDX-License-Identifier: Apache-2.0
// Test coverage for proxy helper functions: shouldBlock, upstreamHostPort

package proxy

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"
)

func TestUpstreamHostPort(t *testing.T) {
	p := &Proxy{
		targetPorts: map[string]int{
			"api.openai.com": 8080,
			"example.com":    3000,
		},
	}

	tests := []struct {
		name   string
		host   string
		scheme string
		expect string
	}{
		{"exact match", "api.openai.com", "https", "api.openai.com:8080"},
		{"subdomain match", "v1.api.openai.com", "https", "v1.api.openai.com:8080"},
		{"no match https", "unknown.com", "https", "unknown.com:443"},
		{"no match http", "unknown.com", "http", "unknown.com:80"},
		{"example.com", "example.com", "http", "example.com:3000"},
		{"subdomain of example.com", "sub.example.com", "http", "sub.example.com:3000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.upstreamHostPort(tt.host, tt.scheme)
			if got != tt.expect {
				t.Errorf("upstreamHostPort(%q, %q) = %q, want %q", tt.host, tt.scheme, got, tt.expect)
			}
		})
	}
}

func TestShouldBlock_MonitorMode(t *testing.T) {
	p := &Proxy{
		cfg: &config.Config{
			Mode: ModeMonitor,
		},
	}
	result := &detector.Summary{TotalDetections: 5}
	block, reason := p.shouldBlock(result, "some content")
	if block {
		t.Error("shouldBlock should return false in monitor mode")
	}
	if reason != "" {
		t.Error("shouldBlock should return empty reason in monitor mode")
	}
}

func TestShouldBlock_NoDetections(t *testing.T) {
	p := &Proxy{
		cfg: &config.Config{
			Mode: ModeBlock,
			Block: config.BlockConfig{
				Threshold: config.SeverityHigh,
			},
		},
	}
	result := &detector.Summary{TotalDetections: 0}
	block, _ := p.shouldBlock(result, "clean content")
	if block {
		t.Error("shouldBlock should return false with no detections")
	}
}
