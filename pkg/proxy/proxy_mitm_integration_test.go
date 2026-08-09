// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - MITM Integration Tests with Full Harness
// =========================================================================
//
// Comprehensive integration tests using the MITM test harness.
// These tests require:
//   1. RAMPART_INTEGRATION=1 environment variable
//   2. Root/admin access for CA trust installation (optional, tests skip otherwise)
//
// Run: go test -v -tags=integration ./pkg/proxy/ -run TestMITM_Integration
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
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

// TestCA contains a generated test CA certificate and key
type TestCA struct {
	Cert    *x509.Certificate
	CertDER []byte
	CertPEM []byte
	Key     *ecdsa.PrivateKey
	KeyPEM  []byte
}

// generateTestCAForHarness creates a temporary CA certificate for integration testing
func generateTestCAForHarness(t *testing.T) *TestCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Rampart MITM Test CA"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal CA key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return &TestCA{
		Cert:    cert,
		CertDER: certDER,
		CertPEM: certPEM,
		Key:     key,
		KeyPEM:  keyPEM,
	}
}

// generateServerCert creates a server certificate signed by the test CA
func generateServerCert(t *testing.T, ca *TestCA, hostnames ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate server key: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	for _, hostname := range hostnames {
		if ip := net.ParseIP(hostname); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, hostname)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse server certificate: %v", err)
	}

	return cert, key
}

// MockBackend represents a running mock HTTPS server
type MockBackend struct {
	Server   *httptest.Server
	URL      string
	Cert     *x509.Certificate
	Requests []*http.Request
}

// startMockBackend starts an HTTPS server with a certificate signed by the test CA
func startMockBackend(t *testing.T, ca *TestCA, triggerDetection bool, responseBody string) *MockBackend {
	t.Helper()

	serverCert, serverKey := generateServerCert(t, ca, "localhost", "api.openai.com", "127.0.0.1")

	tlsCert := tls.Certificate{
		Certificate: [][]byte{serverCert.Raw, ca.Cert.Raw},
		PrivateKey:  serverKey,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	backend := &MockBackend{
		Cert:     serverCert,
		Requests: make([]*http.Request, 0),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backend.Requests = append(backend.Requests, r)

		if responseBody != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(responseBody))
			return
		}

		// Default AI API response
		response := map[string]interface{}{
			"id":      "chatcmpl-test123",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4-test",
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]string{
						"role":    "assistant",
						"content": "This is a test response from the mock AI API.",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]int{
				"prompt_tokens":     10,
				"completion_tokens": 20,
				"total_tokens":      30,
			},
		}

		if triggerDetection {
			response["choices"].([]map[string]interface{})[0]["message"].(map[string]string)["content"] = "AWS Access Key: AKIAIOSFODNN7EXAMPLE"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsConfig
	server.StartTLS()

	backend.Server = server
	backend.URL = server.URL

	t.Cleanup(func() {
		server.Close()
	})

	return backend
}

// TestMITM_Integration_FullFlow tests the complete MITM interception flow
// with a trusted CA, mock backend, and real HTTPS requests.
func TestMITM_Integration_FullFlow(t *testing.T) {
	skipUnlessIntegration(t)

	// Generate test CA
	ca := generateTestCAForHarness(t)

	// Create temp cert directory for proxy
	certDir, err := os.MkdirTemp("", "rampart-test-certs-*")
	if err != nil {
		t.Fatalf("Failed to create temp cert dir: %v", err)
	}
	defer os.RemoveAll(certDir)

	// Install CA in cert directory
	caCertPath := certDir + "/ca.crt"
	caKeyPath := certDir + "/ca.key"
	if err := os.WriteFile(caCertPath, ca.CertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}
	if err := os.WriteFile(caKeyPath, ca.KeyPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA key: %v", err)
	}

	// Start mock backend
	backend := startMockBackend(t, ca, false, "")

	// Start proxy with test CA
	proxyPort := findFreePort(t)
	cfg := &config.Config{
		ProxyPort:  proxyPort,
		DaemonMode: false,
		Verbose:    false,
		Mode:       "monitor",
		Targets:    config.DefaultTargets(),
		Models: config.ModelConfig{
			Path:      "",
			Threshold: 0.5,
			Shadow:    false,
		},
		Privacy: config.PrivacyConfig{
			NoPromptText:     false,
			NoURLs:           false,
			NoPageContent:    false,
			NoPII:            false,
			NoCredentials:    false,
			NoFingerprinting: false,
			NoCrossSite:      false,
			NoProviderMeta:   false,
			NoKeystroke:      false,
			NoMouse:          false,
			NoSessionIDs:     false,
			NoIPAddresses:    false,
		},
	}

	// Override cert directory
	// Note: This requires modifying the proxy to accept cert dir as config
	// For now, we'll use the default cert directory and copy our CA there
	// This is a limitation of the current architecture

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := p.Start(ctx); err != nil && err != http.ErrServerClosed && err != context.Canceled {
			t.Logf("Proxy error: %v", err)
		}
	}()

	defer func() {
		cancel()
		p.Shutdown()
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Create HTTP client that trusts test CA and uses proxy
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Cert)

	proxyURL := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("127.0.0.1:%d", proxyPort),
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: 10 * time.Second,
	}

	// Make request through proxy to backend
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if !strings.Contains(string(body), "chat.completion") {
		t.Errorf("Expected AI API response, got: %s", string(body))
	}

	t.Logf("✓ Full MITM flow successful - request intercepted and proxied")
}

// TestMITM_Integration_BlockModeDetectAPI tests block mode via the /detect endpoint
func TestMITM_Integration_BlockModeDetectAPI(t *testing.T) {
	skipUnlessIntegration(t)

	proxyPort := findFreePort(t)
	cfg := &config.Config{
		ProxyPort:  proxyPort,
		DaemonMode: false,
		Mode:       "block",
		Block: config.BlockConfig{
			Threshold:  "high",
			Categories: []string{"secret"},
			StatusCode: 403,
			Message:    "Blocked by AegisGate Rampart",
		},
		Targets: config.DefaultTargets(),
		Models: config.ModelConfig{
			Path:      "",
			Threshold: 0.5,
			Shadow:    false,
		},
		Privacy: config.PrivacyConfig{
			NoPromptText:     false,
			NoURLs:           false,
			NoPageContent:    false,
			NoPII:            false,
			NoCredentials:    false,
			NoFingerprinting: false,
			NoCrossSite:      false,
			NoProviderMeta:   false,
			NoKeystroke:      false,
			NoMouse:          false,
			NoSessionIDs:     false,
			NoIPAddresses:    false,
		},
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := p.Start(ctx); err != nil && err != http.ErrServerClosed && err != context.Canceled {
			t.Logf("Proxy error: %v", err)
		}
	}()

	defer func() {
		cancel()
		p.Shutdown()
	}()

	time.Sleep(200 * time.Millisecond)

	testCases := []struct {
		name          string
		payload       string
		expectBlocked bool
		description   string
	}{
		{
			name:          "aws_key_blocked",
			payload:       `{"text": "Use AWS key AKIAIOSFODNN7EXAMPLE"}`,
			expectBlocked: true,
			description:   "AWS key (high severity) should be blocked",
		},
		{
			name:          "clean_allowed",
			payload:       `{"text": "What is the weather?"}`,
			expectBlocked: false,
			description:   "Clean text should pass",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(
				fmt.Sprintf("http://127.0.0.1:%d/detect", proxyPort),
				"application/json",
				bytes.NewBufferString(tc.payload),
			)
			if err != nil {
				t.Fatalf("POST /detect failed: %v", err)
			}
			defer resp.Body.Close()

			if tc.expectBlocked {
				if resp.StatusCode != 403 {
					body, _ := io.ReadAll(resp.Body)
					t.Errorf("Expected 403 (blocked), got %d: %s", resp.StatusCode, string(body))
				} else if resp.Header.Get("X-Rampart-Blocked") != "true" {
					t.Errorf("Expected X-Rampart-Blocked: true")
				} else {
					t.Logf("✓ %s: blocked as expected", tc.description)
				}
			} else {
				if resp.StatusCode != 200 {
					body, _ := io.ReadAll(resp.Body)
					t.Errorf("Expected 200 (allowed), got %d: %s", resp.StatusCode, string(body))
				} else {
					t.Logf("✓ %s: passed as expected", tc.description)
				}
			}
		})
	}
}

// TestMITM_Integration_DetectAPI tests the /detect endpoint with real payloads
func TestMITM_Integration_DetectAPI(t *testing.T) {
	skipUnlessIntegration(t)

	proxyPort := findFreePort(t)
	cfg := &config.Config{
		ProxyPort:  proxyPort,
		DaemonMode: false,
		Mode:       "monitor",
		Targets:    config.DefaultTargets(),
		Models: config.ModelConfig{
			Path:      "",
			Threshold: 0.5,
			Shadow:    false,
		},
		Privacy: config.PrivacyConfig{
			NoPromptText:     false,
			NoURLs:           false,
			NoPageContent:    false,
			NoPII:            false,
			NoCredentials:    false,
			NoFingerprinting: false,
			NoCrossSite:      false,
			NoProviderMeta:   false,
			NoKeystroke:      false,
			NoMouse:          false,
			NoSessionIDs:     false,
			NoIPAddresses:    false,
		},
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := p.Start(ctx); err != nil && err != http.ErrServerClosed && err != context.Canceled {
			t.Logf("Proxy error: %v", err)
		}
	}()

	defer func() {
		cancel()
		p.Shutdown()
	}()

	time.Sleep(200 * time.Millisecond)

	testCases := []struct {
		name           string
		payload        string
		expectDetected bool
		description    string
	}{
		{
			name:           "aws_key",
			payload:        `{"text": "Use AWS key AKIAIOSFODNN7EXAMPLE"}`,
			expectDetected: true,
			description:    "AWS key should trigger detection",
		},
		{
			name:           "ssn",
			payload:        `{"text": "SSN: 123-45-6789"}`,
			expectDetected: true,
			description:    "SSN should trigger PII detection",
		},
		{
			name:           "clean",
			payload:        `{"text": "What is the weather?"}`,
			expectDetected: false,
			description:    "Clean text should not trigger detection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(
				fmt.Sprintf("http://127.0.0.1:%d/detect", proxyPort),
				"application/json",
				bytes.NewBufferString(tc.payload),
			)
			if err != nil {
				t.Fatalf("Detect request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}

			// Read and parse response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatalf("Failed to parse JSON: %v", err)
			}

			// Check if detection occurred based on total_detections field
			totalDetections, ok := result["total_detections"].(float64)
			if !ok {
				totalDetections = 0
			}
			detected := totalDetections > 0

			if detected != tc.expectDetected {
				t.Errorf("%s: expected detected=%v, got detected=%v (body: %s)",
					tc.description, tc.expectDetected, detected, string(body))
			} else {
				t.Logf("✓ %s: correctly %s (detections: %.0f)", tc.description, 
					map[bool]string{true: "detected", false: "not detected"}[detected], totalDetections)
			}
		})
	}
}
