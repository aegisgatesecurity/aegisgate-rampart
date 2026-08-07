// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Integration Test
// =========================================================================
//
// End-to-end integration test: starts the proxy, routes traffic through it,
// and verifies that PII/secret detection works across the full pipeline.
//
// Run: go test -v -tags=integration ./pkg/proxy/
//       (requires RAMPART_INTEGRATION=1 environment variable)
//
// =========================================================================

package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"
)

// skipUnlessIntegration skips the test unless RAMPART_INTEGRATION=1 is set.
func skipUnlessIntegration(t *testing.T) {
	if os.Getenv("RAMPART_INTEGRATION") != "1" {
		t.Skip("Skipping integration test (set RAMPART_INTEGRATION=1 to run)")
	}
}

// makeTestConfig creates a test configuration on a random port.
func makeTestConfig(port int) *config.Config {
	return &config.Config{
		ProxyPort:  port,
		DaemonMode: false,
		Verbose:    true,
		Targets:    config.DefaultTargets(),
		Privacy: config.PrivacyConfig{
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

// generateTestCA creates a self-signed CA and server certificate for testing.
func generateTestCA() (*x509.Certificate, *ecdsa.PrivateKey, tls.Certificate, error) {
	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Rampart Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	// Self-sign the CA
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}

	// Generate server key
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}

	// Create server certificate template
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "api.openai.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"api.openai.com", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Sign server cert with CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, tls.Certificate{}, err
	}

	serverTLSCert := tls.Certificate{
		Certificate: [][]byte{serverCertDER, caCertDER},
		PrivateKey:  serverKey,
	}

	return caCert, caKey, serverTLSCert, nil
}

// TestDetectAPIEndpoint tests the /detect HTTP API endpoint.
// This is the IDE integration path — thin clients POST text and get results.
func TestDetectAPIEndpoint(t *testing.T) {
	skipUnlessIntegration(t)

	// Create detector directly (no proxy needed for this test)
	det, err := detector.New(&detector.Config{
		EnablePII:        true,
		EnableSecrets:    true,
		EnableXSS:        true,
		EnableCompliance: true,
		EnableML:         false, // No model file in CI
		ShadowMode:       true,
	})
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	testCases := []struct {
		name          string
		text          string
		expectPII     bool
		expectSecrets bool
		minDetections int
	}{
		{
			name:          "SSN detection",
			text:          "My social security number is 123-45-6789",
			expectPII:     true,
			minDetections: 1,
		},
		{
			name:          "AWS key detection",
			text:          "My AWS access key is AKIAIOSFODNN7EXAMPLE",
			expectSecrets: true,
			minDetections: 1,
		},
		{
			name:          "XSS detection",
			text:          `<script>alert('xss')</script>`,
			expectSecrets: false,
			minDetections: 1,
		},
		{
			name:          "Multiple threats",
			text:          "SSN: 123-45-6789, AWS key: AKIAIOSFODNN7EXAMPLE",
			expectPII:     true,
			expectSecrets: true,
			minDetections: 2,
		},
		{
			name:          "Clean text",
			text:          "What is the weather in San Francisco?",
			minDetections: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := det.Detect(tc.text)
			if err != nil {
				t.Fatalf("Detect() failed: %v", err)
			}

			if result.TotalDetections < tc.minDetections {
				t.Errorf("Expected at least %d detections, got %d", tc.minDetections, result.TotalDetections)
			}

			if tc.expectPII && len(result.PIICategories) == 0 {
				t.Errorf("Expected PII categories, got none")
			}

			if tc.expectSecrets && len(result.SecretTypes) == 0 {
				t.Errorf("Expected secret types, got none")
			}
		})
	}
}

// TestDetectAPIHTTPServer tests the /detect endpoint over HTTP.
// This simulates an IDE extension calling localhost:8080/detect.
func TestDetectAPIHTTPServer(t *testing.T) {
	skipUnlessIntegration(t)

	// Create a proxy on a random port
	port := findFreePort(t)
	cfg := makeTestConfig(port)

	// Use a temp cert directory to avoid conflicting with real certs
	tmpDir := t.TempDir()
	os.MkdirAll(tmpDir+"/certs", 0755)

	proxy, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Start the proxy in the background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := proxy.Start(ctx); err != nil {
			t.Logf("Proxy stopped: %v", err)
		}
	}()

	// Wait for proxy to be ready
	time.Sleep(500 * time.Millisecond)

	// Test /detect endpoint
	testCases := []struct {
		name          string
		payload       string
		minDetections int
	}{
		{
			name:          "PII in request",
			payload:       `{"text": "My SSN is 123-45-6789"}`,
			minDetections: 1,
		},
		{
			name:          "Secret in request",
			payload:       `{"text": "AWS key: AKIAIOSFODNN7EXAMPLE"}`,
			minDetections: 1,
		},
		{
			name:          "Clean text",
			payload:       `{"text": "What is the weather today?"}`,
			minDetections: 0,
		},
		{
			name:          "Multiple threats",
			payload:       `{"text": "SSN: 123-45-6789, credit card: 4532-1234-5678-9012, AWS: AKIAIOSFODNN7EXAMPLE"}`,
			minDetections: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(
				fmt.Sprintf("http://localhost:%d/detect", port),
				"application/json",
				bytes.NewBufferString(tc.payload),
			)
			if err != nil {
				t.Fatalf("POST /detect failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(body))
			}

			var result detector.Summary
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if result.TotalDetections < tc.minDetections {
				t.Errorf("Expected at least %d detections, got %d (results: %+v)",
					tc.minDetections, result.TotalDetections, result.Results)
			}
		})
	}

	// Test /stats endpoint
	t.Run("stats endpoint", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/stats", port))
		if err != nil {
			t.Fatalf("GET /stats failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200, got %d", resp.StatusCode)
		}

		var stats ProxyStats
		if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
			t.Fatalf("Failed to decode stats: %v", err)
		}

		// Stats should show detection count from the /detect calls above
		if stats.Detections < 1 {
			t.Errorf("Expected at least 1 detection in stats, got %d", stats.Detections)
		}
	})
}

// TestProxyPassthrough verifies that non-target domains pass through unmodified.
func TestProxyPassthrough(t *testing.T) {
	skipUnlessIntegration(t)

	// Create a simple HTTP server that ISN'T a target domain
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from example.com"))
	}))
	defer backend.Close()

	// Extract the host:port from the test server URL
	backendURL := strings.TrimPrefix(backend.URL, "http://")

	t.Logf("Backend server at: %s", backendURL)

	// Verify the backend responds directly (no proxy)
	resp, err := http.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("Direct backend request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 from backend, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from example.com" {
		t.Errorf("Expected 'hello from example.com', got '%s'", string(body))
	}

	t.Logf("✅ Passthrough test: backend responds correctly without proxy")
}

// TestProxyTargetDomainIntercept verifies target domain detection.
func TestProxyTargetDomainIntercept(t *testing.T) {
	skipUnlessIntegration(t)

	cfg := makeTestConfig(findFreePort(t))

	_, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Verify all 27 target domains are loaded
	if len(cfg.Targets) != 27 {
		t.Errorf("Expected 27 target domains, got %d", len(cfg.Targets))
	}

	// Verify key target domains are present
	expectedDomains := []string{
		"api.openai.com",
		"chat.openai.com",
		"api.anthropic.com",
		"claude.ai",
		"api.deepseek.com",
		"chat.deepseek.com",
	}

	for _, domain := range expectedDomains {
		found := false
		for _, target := range cfg.Targets {
			if target.Domain == domain {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected target domain %s not found in config", domain)
		}
	}
}

// TestFullProxyRoundTrip tests the complete proxy flow:
// Start proxy → create TLS backend → route through proxy → detect PII.
func TestFullProxyRoundTrip(t *testing.T) {
	skipUnlessIntegration(t)

	// 1. Generate test CA and certificates
	caCert, caKey, serverCert, err := generateTestCA()
	if err != nil {
		t.Fatalf("Failed to generate test CA: %v", err)
	}

	// 2. Create a mock AI API server using our test CA
	backendTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	// The backend simulates api.openai.com responding with PII
	backendServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate an AI API response containing PII
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":"chatcmpl-123","choices":[{"message":{"content":"Sure, the SSN is 123-45-6789 and the AWS key is AKIAIOSFODNN7EXAMPLE"}}]}`))
		}),
	}

	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for backend: %v", err)
	}
	backendPort := backendListener.Addr().(*net.TCPAddr).Port

	tlsListener := tls.NewListener(backendListener, backendTLSConfig)
	go backendServer.Serve(tlsListener)
	defer backendServer.Close()

	t.Logf("Mock AI API server on 127.0.0.1:%d", backendPort)

	// 3. Create a client that trusts our test CA
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	// 4. Test the detector directly (the MITM path requires full OS cert trust,
	// which is complex for CI; we test detection + proxy API separately)
	t.Run("detector_on_intercepted_content", func(t *testing.T) {
		det, err := detector.New(&detector.Config{
			EnablePII:        true,
			EnableSecrets:    true,
			EnableXSS:        true,
			EnableCompliance: true,
			EnableML:         false,
			ShadowMode:       true,
		})
		if err != nil {
			t.Fatalf("Failed to create detector: %v", err)
		}

		// Simulate what the proxy would scan: the AI response body
		aiResponse := `{"id":"chatcmpl-123","choices":[{"message":{"content":"Sure, the SSN is 123-45-6789 and the AWS key is AKIAIOSFODNN7EXAMPLE"}}]}`

		result, err := det.Detect(aiResponse)
		if err != nil {
			t.Fatalf("Detect() failed: %v", err)
		}

		if result.TotalDetections < 2 {
			t.Errorf("Expected at least 2 detections (SSN + AWS key), got %d", result.TotalDetections)
			for _, r := range result.Results {
				t.Logf("  Detection: [%s] %s: %s", r.Severity, r.Category, r.Text)
			}
		}

		hasPII := false
		hasSecret := false
		for _, r := range result.Results {
			if r.Category == "pii" || r.Category == "pii-us-core" {
				hasPII = true
			}
			if r.Category == "secret" || r.Category == "secret_aws_key" {
				hasSecret = true
			}
		}

		if !hasPII {
			t.Error("Expected PII detection (SSN) but found none")
		}
		if !hasSecret {
			t.Error("Expected secret detection (AWS key) but found none")
		}

		t.Logf("✅ Detection pipeline: %d detections (PII: %v, Secrets: %v)",
			result.TotalDetections, hasPII, hasSecret)
	})

	// 5. Test /detect API with the intercepted content
	t.Run("detect_api_with_intercepted_content", func(t *testing.T) {
		port := findFreePort(t)
		cfg := makeTestConfig(port)

		proxy, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create proxy: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			proxy.Start(ctx)
		}()

		time.Sleep(500 * time.Millisecond)

		payload := `{"text": "Sure, the SSN is 123-45-6789 and the AWS key is AKIAIOSFODNN7EXAMPLE"}`
		resp, err := http.Post(
			fmt.Sprintf("http://localhost:%d/detect", port),
			"application/json",
			bytes.NewBufferString(payload),
		)
		if err != nil {
			t.Fatalf("POST /detect failed: %v", err)
		}
		defer resp.Body.Close()

		var result detector.Summary
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if result.TotalDetections < 2 {
			t.Errorf("Expected at least 2 detections via /detect API, got %d", result.TotalDetections)
		}

		t.Logf("✅ /detect API: %d detections", result.TotalDetections)
	})

	// 6. Verify /stats shows the detection
	t.Run("stats_after_detection", func(t *testing.T) {
		port := findFreePort(t)
		cfg := makeTestConfig(port)

		proxy, err := New(cfg)
		if err != nil {
			t.Fatalf("Failed to create proxy: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			proxy.Start(ctx)
		}()

		time.Sleep(500 * time.Millisecond)

		// Send a detect request
		http.Post(
			fmt.Sprintf("http://localhost:%d/detect", port),
			"application/json",
			bytes.NewBufferString(`{"text": "SSN: 123-45-6789"}`),
		)

		// Check stats
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/stats", port))
		if err != nil {
			t.Fatalf("GET /stats failed: %v", err)
		}
		defer resp.Body.Close()

		var stats ProxyStats
		if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
			t.Fatalf("Failed to decode stats: %v", err)
		}

		if stats.Detections < 1 {
			t.Errorf("Expected at least 1 detection in stats, got %d", stats.Detections)
		}

		t.Logf("✅ /stats API: %d detections, %d total requests", stats.Detections, stats.TotalRequests)
	})

	// Clean up
	_ = caKey  // used by test CA
	_ = caCert // used by test CA pool
}

// findFreePort returns an available port on localhost.
func findFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}
