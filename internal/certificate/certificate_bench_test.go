package certificate

import (
	"testing"
)

// BenchmarkTLS benchmarks TLS certificate generation for MITM proxying.
// This is the core crypto operation in Rampart's HTTPS interception path.
func BenchmarkTLS(b *testing.B) {
	mgr := NewManager()

	// Pre-generate the CA certificate so benchmark measures only
	// the per-domain proxy cert generation (the hot path).
	_, err := mgr.GenerateSelfSigned()
	if err != nil {
		b.Fatalf("GenerateSelfSigned: %v", err)
	}

	// Realistic AI API hostnames that Rampart intercepts.
	hostnames := []string{
		"api.openai.com",
		"chatgpt.com",
		"api.anthropic.com",
		"claude.ai",
		"generativelanguage.googleapis.com",
		"gemini.google.com",
		"api.perplexity.ai",
		"api.x.ai",
		"grok.com",
		"api.mistral.ai",
		"chat.mistral.ai",
		"api.deepseek.com",
		"chat.deepseek.com",
		"api.copilot.microsoft.com",
		"meta.ai",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostname := hostnames[i%len(hostnames)]
		// Clear cache to force generation each iteration.
		mgr.ClearCache()
		// Re-generate the CA (ClearCache removes it).
		_, err := mgr.GenerateSelfSigned()
		if err != nil {
			b.Fatalf("GenerateSelfSigned: %v", err)
		}
		_, err = mgr.GenerateProxyCertificate(hostname)
		if err != nil {
			b.Fatalf("GenerateProxyCertificate(%s): %v", hostname, err)
		}
	}
}

// BenchmarkTLSSelfSigned benchmarks self-signed CA certificate generation.
func BenchmarkTLSSelfSigned(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr := NewManager()
		_, err := mgr.GenerateSelfSigned()
		if err != nil {
			b.Fatalf("GenerateSelfSigned: %v", err)
		}
	}
}

// BenchmarkTLSProxyCertCached benchmarks proxy cert generation with caching.
// First call generates; subsequent calls hit the cache.
func BenchmarkTLSProxyCertCached(b *testing.B) {
	mgr := NewManager()
	_, err := mgr.GenerateSelfSigned()
	if err != nil {
		b.Fatalf("GenerateSelfSigned: %v", err)
	}

	// Pre-warm cache with a single hostname.
	_, err = mgr.GenerateProxyCertificate("api.openai.com")
	if err != nil {
		b.Fatalf("GenerateProxyCertificate: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mgr.GenerateProxyCertificate("api.openai.com")
		if err != nil {
			b.Fatalf("GenerateProxyCertificate (cached): %v", err)
		}
	}
}

// BenchmarkTLSMultipleHosts benchmarks generating certs for many different hosts
// (simulates the proxy intercepting traffic to many AI services concurrently).
func BenchmarkTLSMultipleHosts(b *testing.B) {
	hostnames := []string{
		"api.openai.com",
		"chatgpt.com",
		"api.anthropic.com",
		"claude.ai",
		"generativelanguage.googleapis.com",
		"gemini.google.com",
		"api.perplexity.ai",
		"api.x.ai",
		"grok.com",
		"api.mistral.ai",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr := NewManager()
		_, err := mgr.GenerateSelfSigned()
		if err != nil {
			b.Fatalf("GenerateSelfSigned: %v", err)
		}
		for _, host := range hostnames {
			_, err := mgr.GenerateProxyCertificate(host)
			if err != nil {
				b.Fatalf("GenerateProxyCertificate(%s): %v", host, err)
			}
		}
	}
}
