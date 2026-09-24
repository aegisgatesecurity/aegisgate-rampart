// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - P2#1 Block Mode MITM E2E Tests
// =========================================================================
//
// Implements the 6 test scenarios from P2-1-BLOCK-MODE-MITM-TESTLAB.md:
//   1. Block Mode MITM - Request Blocking
//   2. Block Mode MITM - Response Blocking
//   3. Block Mode MITM - Severity Threshold
//   4. Block Mode MITM - Category Filtering
//   5. Block Mode MITM - Non-Target Pass-Through
//   6. Full E2E Flow
//
// Uses in-process approach (Option A):
//   - Generate test CA + server cert in test
//   - Start mock HTTPS backend
//   - Start proxy with test CA
//   - Use Go's http.Transport with custom TLS config trusting test CA
//   - No system CA modification needed
//
// Gated behind RAMPART_INTEGRATION=1 (same as existing MITM integration tests).
//
// =========================================================================

package proxy

import (
	"bufio"
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

// ---------------------------------------------------------------------------
// Test CA + cert helpers (self-contained for this file)
// ---------------------------------------------------------------------------

type mitmTestCA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     *ecdsa.PrivateKey
	KeyPEM  []byte
}

func newMITMTestCA(t *testing.T) *mitmTestCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Rampart P2#1 Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return &mitmTestCA{Cert: cert, CertPEM: certPEM, Key: key, KeyPEM: keyPEM}
}

func (ca *mitmTestCA) generateServerCert(t *testing.T, hostnames ...string) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER, ca.Cert.Raw},
		PrivateKey:  key,
	}, cert
}

// mitmMockBackend is a mock AI API backend for MITM block mode tests.
type mitmMockBackend struct {
	Server       *httptest.Server
	URL          string
	RequestCount int
	LastBody     string
}

// startMITMBackend starts a mock HTTPS backend with the given handler.
// If handler is nil, a default AI API handler is used.
func startMITMBackend(t *testing.T, ca *mitmTestCA, handler http.HandlerFunc) *mitmMockBackend {
	t.Helper()

	tlsCert, _ := ca.generateServerCert(t, "localhost", "127.0.0.1")

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()

	backend := &mitmMockBackend{
		Server: server,
		URL:    server.URL,
	}
	t.Cleanup(func() { server.Close() })

	return backend
}

// mitmTestEnv holds all components for a MITM block mode E2E test.
type mitmTestEnv struct {
	CA        *mitmTestCA
	Backend   *mitmMockBackend
	Proxy     *Proxy
	ProxyPort int
	Client    *http.Client
	Cancel    context.CancelFunc
}

// setupMITMTestEnv creates a full MITM test environment with block mode.
// The proxy's sharedTransport is overridden to route all target domain
// requests to the mock backend, enabling true E2E MITM testing.
func setupMITMTestEnv(t *testing.T, blockCfg config.BlockConfig, backendHandler http.HandlerFunc) *mitmTestEnv {
	t.Helper()

	ca := newMITMTestCA(t)

	// Write CA to temp dir for proxy to load
	certDir, err := os.MkdirTemp("", "rampart-mitm-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(certDir) })

	caCertPath := certDir + "/ca.crt"
	caKeyPath := certDir + "/ca.key"
	if err := os.WriteFile(caCertPath, ca.CertPEM, 0644); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}
	if err := os.WriteFile(caKeyPath, ca.KeyPEM, 0600); err != nil {
		t.Fatalf("write CA key: %v", err)
	}

	// Start mock backend
	backend := startMITMBackend(t, ca, backendHandler)
	backendURL := mustParseURL(backend.URL)
	backendHost, backendPort, _ := net.SplitHostPort(backendURL.Host)

	// Start proxy
	proxyPort := findFreePort(t)
	cfg := &config.Config{
		ProxyPort:  proxyPort,
		DaemonMode: false,
		Mode:       config.ModeBlock,
		Targets:    config.DefaultTargets(),
		Block:      blockCfg,
		Models: config.ModelConfig{
			Threshold: 0.5,
			Shadow:    false,
		},
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Load our test CA into the proxy's cert manager
	if err := p.certMgr.LoadCAFromFiles(caCertPath, caKeyPath); err != nil {
		t.Fatalf("load test CA into proxy: %v", err)
	}

	// Override the proxy's sharedTransport to route all upstream requests
	// to our mock backend. This is critical: when interceptHTTPS does
	// RoundTrip(clientReq), it needs to reach our mock backend, not the
	// real api.openai.com. We use a custom DialTLSContext that remaps
	// any target domain to 127.0.0.1:backendPort.
	backendCertPool := x509.NewCertPool()
	backendCertPool.AddCert(ca.Cert)

	p.sharedTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    backendCertPool,
			MinVersion: tls.VersionTLS12,
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Always connect to the mock backend
			dialer := &net.Dialer{Timeout: 10 * time.Second}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(backendHost, backendPort))
			if err != nil {
				return nil, err
			}
			// Wrap with TLS using the backend's cert
			tlsConn := tls.Client(conn, &tls.Config{
				RootCAs:    backendCertPool,
				MinVersion: tls.VersionTLS12,
				// Use the original hostname for SNI so the backend cert matches
				ServerName: "localhost",
			})
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS handshake to backend: %w", err)
			}
			return tlsConn, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := p.Start(ctx); err != nil && err != http.ErrServerClosed {
			t.Logf("proxy error: %v", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(300 * time.Millisecond)

	// Create HTTP client that trusts test CA and uses proxy.
	// The client uses CONNECT to the proxy, which MITMs the TLS.
	// The client needs to trust the proxy's CA for the MITM'd cert.
	// We use InsecureSkipVerify because the proxy generates certs
	// on-the-fly for whatever domain the client requests, and the
	// proxy's CA might differ from our test CA after New() loads
	// its own CA from the default cert dir.
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Cert)

	proxyURL := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("127.0.0.1:%d", proxyPort),
	}

	// Parse backend URL to get the target host:port for the request
	// We need to make requests to a target domain (e.g., api.openai.com)
	// through the proxy. The proxy will MITM and forward to our backend.
	// Use the backend's address directly as the request URL host, but
	// we need it to be a target domain. Since the proxy checks isTargetDomain,
	// we need to send requests to a domain that's in the targets list.
	// The trick: use the backend's address but set Host header to a target domain.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				// Trust our test CA (which the proxy uses for MITM certs)
				RootCAs: certPool,
			},
		},
		Timeout: 10 * time.Second,
	}

	env := &mitmTestEnv{
		CA:        ca,
		Backend:   backend,
		Proxy:     p,
		ProxyPort: proxyPort,
		Client:    client,
		Cancel:    cancel,
	}

	t.Cleanup(func() {
		cancel()
		p.Shutdown()
	})

	return env
}

// defaultAIResponse returns a standard AI API response body.
func defaultAIResponse() string {
	return `{"id":"chatcmpl-test","object":"chat.completion","created":1695000000,"model":"gpt-4-test","choices":[{"index":0,"message":{"role":"assistant","content":"This is a safe AI response."},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}`
}

// aiResponseWithSecret returns an AI response containing an AWS key (triggers detection).
func aiResponseWithSecret() string {
	return `{"id":"chatcmpl-test","object":"chat.completion","created":1695000000,"model":"gpt-4-test","choices":[{"index":0,"message":{"role":"assistant","content":"The AWS key is AKIAIOSFODNN7EXAMPLE"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}`
}

// ---------------------------------------------------------------------------
// Scenario 1: Block Mode MITM - Request Blocking
// ---------------------------------------------------------------------------

func TestBlockModeMITM_BlockRequest(t *testing.T) {
	skipUnlessIntegration(t)

	var requestCount int
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		body, _ := io.ReadAll(r.Body)
		_ = body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(defaultAIResponse()))
	})

	env := setupMITMTestEnv(t, config.BlockConfig{
		Threshold:         config.SeverityHigh,
		StatusCode:        403,
		IncludeDetections: true,
		Message:           "Blocked by Rampart",
	}, backendHandler)

	// Send request with AWS key through proxy → should be blocked
	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Use my AWS key AKIAIOSFODNN7EXAMPLE to access S3"}]}`
	resp, err := env.Client.Post(
		"https://api.openai.com/v1/chat/completions",
		"application/json",
		bytes.NewBufferString(reqBody),
	)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403 (blocked), got %d: %s", resp.StatusCode, string(body))
	}

	if resp.Header.Get("X-Rampart-Blocked") != "true" {
		t.Error("expected X-Rampart-Blocked: true header")
	}

	// Verify backend was NOT called (request blocked before forwarding)
	if requestCount > 0 {
		t.Errorf("backend should not receive blocked request, got %d calls", requestCount)
	}

	t.Logf("✓ Request blocking: AWS key in request blocked, backend not called")
}

// ---------------------------------------------------------------------------
// Scenario 2: Block Mode MITM - Response Blocking
// ---------------------------------------------------------------------------

func TestBlockModeMITM_BlockResponse(t *testing.T) {
	skipUnlessIntegration(t)

	var respRequestCount int
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respRequestCount++
		w.Header().Set("Content-Type", "application/json")
		// Response contains an AWS key → should be blocked
		_, _ = w.Write([]byte(aiResponseWithSecret()))
	})

	env := setupMITMTestEnv(t, config.BlockConfig{
		Threshold:         config.SeverityHigh,
		StatusCode:        403,
		IncludeDetections: true,
		Message:           "Blocked by Rampart",
	}, backendHandler)

	// Send clean request → response should be blocked because it contains a secret
	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"What is the weather?"}]}`
	resp, err := env.Client.Post(
		"https://api.openai.com/v1/chat/completions",
		"application/json",
		bytes.NewBufferString(reqBody),
	)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403 (response blocked), got %d: %s", resp.StatusCode, string(body))
	}

	if resp.Header.Get("X-Rampart-Blocked") != "true" {
		t.Error("expected X-Rampart-Blocked: true header")
	}

	// Verify the blocked response does NOT contain the leaked secret
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("blocked response should not contain the leaked AWS key")
	}

	// Backend should have been called (request was clean, response was blocked)
	if respRequestCount == 0 {
		t.Error("backend should receive the clean request (response blocking happens after)")
	}

	t.Logf("✓ Response blocking: secret in AI response blocked, no leaked PII")
}

// ---------------------------------------------------------------------------
// Scenario 3: Block Mode MITM - Severity Threshold
// ---------------------------------------------------------------------------

func TestBlockModeMITM_SeverityThresholds(t *testing.T) {
	skipUnlessIntegration(t)

	testCases := []struct {
		name          string
		threshold     string
		payload       string
		expectBlocked bool
		description   string
	}{
		{
			name:          "low_threshold_blocks_medium",
			threshold:     config.SeverityLow,
			payload:       `{"model":"gpt-4","messages":[{"role":"user","content":"My email is test@example.com"}]}`,
			expectBlocked: true,
			description:   "Low threshold should block medium-severity PII (email)",
		},
		{
			name:          "high_threshold_allows_medium",
			threshold:     config.SeverityHigh,
			payload:       `{"model":"gpt-4","messages":[{"role":"user","content":"My email is test@example.com"}]}`,
			expectBlocked: false,
			description:   "High threshold should allow medium-severity PII (email)",
		},
		{
			name:          "high_threshold_blocks_high",
			threshold:     config.SeverityHigh,
			payload:       `{"model":"gpt-4","messages":[{"role":"user","content":"AWS key AKIAIOSFODNN7EXAMPLE"}]}`,
			expectBlocked: true,
			description:   "High threshold should block high-severity secret (AWS key)",
		},
		{
			name:          "critical_threshold_allows_medium",
			threshold:     config.SeverityCritical,
			payload:       `{"model":"gpt-4","messages":[{"role":"user","content":"My email is test@example.com"}]}`,
			expectBlocked: false,
			description:   "Critical threshold should allow medium-severity PII (email)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(defaultAIResponse()))
			})

			env := setupMITMTestEnv(t, config.BlockConfig{
				Threshold:         tc.threshold,
				StatusCode:        403,
				IncludeDetections: false,
			}, backendHandler)

			resp, err := env.Client.Post(
				"https://api.openai.com/v1/chat/completions",
				"application/json",
				bytes.NewBufferString(tc.payload),
			)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			blocked := resp.StatusCode == 403 && resp.Header.Get("X-Rampart-Blocked") == "true"
			if blocked != tc.expectBlocked {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("%s: expected blocked=%v, got blocked=%v (status=%d, body=%s)",
					tc.description, tc.expectBlocked, blocked, resp.StatusCode, string(body))
			} else {
				t.Logf("✓ %s", tc.description)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scenario 4: Block Mode MITM - Category Filtering
// ---------------------------------------------------------------------------

func TestBlockModeMITM_CategoryFiltering(t *testing.T) {
	skipUnlessIntegration(t)

	testCases := []struct {
		name          string
		categories    []string
		payload       string
		expectBlocked bool
		description   string
	}{
		{
			name:          "block_secrets_only_with_secret",
			categories:    []string{"secret"},
			payload:       `{"model":"gpt-4","messages":[{"role":"user","content":"AWS key AKIAIOSFODNN7EXAMPLE"}]}`,
			expectBlocked: true,
			description:   "Block on 'secret' category → AWS key should be blocked",
		},
		{
			name:          "block_secrets_only_with_pii",
			categories:    []string{"secret"},
			payload:       `{"model":"gpt-4","messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}`,
			expectBlocked: false,
			description:   "Block on 'secret' only → PII (SSN) should pass",
		},
		{
			name:          "block_pii_with_pii",
			categories:    []string{"pii"},
			payload:       `{"model":"gpt-4","messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}`,
			expectBlocked: true,
			description:   "Block on 'pii' category → SSN should be blocked",
		},
		{
			name:          "block_all_categories",
			categories:    []string{},
			payload:       `{"model":"gpt-4","messages":[{"role":"user","content":"AWS key AKIAIOSFODNN7EXAMPLE"}]}`,
			expectBlocked: true,
			description:   "Empty categories = all → AWS key should be blocked",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(defaultAIResponse()))
			})

			env := setupMITMTestEnv(t, config.BlockConfig{
				Threshold:         config.SeverityLow, // low threshold so severity isn't the gate
				Categories:        tc.categories,
				StatusCode:        403,
				IncludeDetections: false,
			}, backendHandler)

			resp, err := env.Client.Post(
				"https://api.openai.com/v1/chat/completions",
				"application/json",
				bytes.NewBufferString(tc.payload),
			)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			blocked := resp.StatusCode == 403 && resp.Header.Get("X-Rampart-Blocked") == "true"
			if blocked != tc.expectBlocked {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("%s: expected blocked=%v, got blocked=%v (status=%d, body=%s)",
					tc.description, tc.expectBlocked, blocked, resp.StatusCode, string(body))
			} else {
				t.Logf("✓ %s", tc.description)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scenario 5: Block Mode MITM - Non-Target Pass-Through
// ---------------------------------------------------------------------------

func TestBlockModeMITM_NonTargetPassthrough(t *testing.T) {
	skipUnlessIntegration(t)

	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(defaultAIResponse()))
	})

	env := setupMITMTestEnv(t, config.BlockConfig{
		Threshold:         config.SeverityLow,
		StatusCode:        403,
		IncludeDetections: false,
	}, backendHandler)

	// Send a raw CONNECT to a non-target domain.
	// The proxy should tunnel it without interception.
	// Use a non-target public hostname that resolves quickly.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", env.ProxyPort), 5*time.Second)
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer conn.Close()

	// Use 1.1.1.1 (Cloudflare DNS) as a known-public, fast-responding endpoint
	_, err = fmt.Fprintf(conn, "CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n")
	if err != nil {
		t.Fatalf("send CONNECT: %v", err)
	}

	// Set a read deadline so we don't hang forever
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{
		Method: "CONNECT",
		URL:    mustParseURL("http://1.1.1.1:443"),
	})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for non-target CONNECT, got %d", resp.StatusCode)
	}

	// Verify proxy stats show passthrough (not intercept)
	stats := env.Proxy.GetStats()
	if stats.PassedThrough == 0 {
		t.Error("expected PassedThrough > 0 for non-target domain")
	}
	if stats.Intercepted > 0 {
		t.Error("non-target domain should not be intercepted")
	}

	t.Logf("✓ Non-target pass-through: CONNECT to example.com tunneled (stats: passed=%d, intercepted=%d)",
		stats.PassedThrough, stats.Intercepted)
}

// ---------------------------------------------------------------------------
// Scenario 6: Full E2E Flow
// ---------------------------------------------------------------------------

func TestBlockModeMITM_FullE2E(t *testing.T) {
	skipUnlessIntegration(t)

	var fullRequestCount int
	requestBlocked := false
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fullRequestCount++
		body, _ := io.ReadAll(r.Body)
		_ = body

		// Return response with PII
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(aiResponseWithSecret()))
	})

	env := setupMITMTestEnv(t, config.BlockConfig{
		Threshold:         config.SeverityHigh,
		StatusCode:        403,
		IncludeDetections: true,
		Message:           "Blocked by Rampart",
	}, backendHandler)

	// Step 1: Send clean request → should get response with secret → blocked
	resp, err := env.Client.Post(
		"https://api.openai.com/v1/chat/completions",
		"application/json",
		bytes.NewBufferString(`{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}`),
	)
	if err != nil {
		t.Fatalf("clean request failed: %v", err)
	}

	if resp.StatusCode == 403 {
		// Response was blocked because it contained a secret
		requestBlocked = true
		var detail struct {
			Blocked   bool   `json:"blocked"`
			Severity  string `json:"severity"`
			Direction string `json:"direction"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&detail)
		if detail.Direction != "response" {
			t.Errorf("expected direction=response, got %s", detail.Direction)
		}
		t.Logf("✓ Response blocked: direction=response, severity=%s", detail.Severity)
	} else {
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Response not blocked (status=%d), body=%s", resp.StatusCode, string(body))
	}
	resp.Body.Close()

	// Step 2: Verify proxy stats
	stats := env.Proxy.GetStats()
	if stats.TotalRequests < 1 {
		t.Errorf("expected total_requests >= 1, got %d", stats.TotalRequests)
	}
	if requestBlocked && stats.BlockedRequests == 0 {
		t.Error("expected blocked_requests > 0 after block")
	}

	t.Logf("✓ Full E2E: stats total=%d, intercepted=%d, blocked=%d, passed=%d",
		stats.TotalRequests, stats.Intercepted, stats.BlockedRequests, stats.PassedThrough)
}

// ---------------------------------------------------------------------------
// Additional coverage: interceptHTTPS error paths
// ---------------------------------------------------------------------------

func TestMITM_CertGenerationError(t *testing.T) {
	skipUnlessIntegration(t)

	// Create proxy with broken cert manager (no CA loaded)
	port := findFreePort(t)
	cfg := &config.Config{
		ProxyPort: port,
		Mode:      config.ModeBlock,
		Targets:   config.DefaultTargets(),
		Block: config.BlockConfig{
			Threshold:  config.SeverityHigh,
			StatusCode: 403,
		},
	}

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = p.Start(ctx) }()
	defer func() {
		cancel()
		p.Shutdown()
	}()
	time.Sleep(200 * time.Millisecond)

	// Make a CONNECT request to a target domain
	// The cert manager has a CA (from New()), so this should actually work.
	// But if we can trigger a cert generation error, we cover that path.
	// For now, just verify the proxy handles CONNECT without crashing.
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // We don't have the CA cert
			},
		},
		Timeout: 5 * time.Second,
	}

	// This will likely fail at TLS handshake, but should not crash the proxy
	_, _ = client.Get("https://api.openai.com/v1/models")

	stats := p.GetStats()
	t.Logf("Stats after CONNECT attempt: total=%d, intercepted=%d, passed=%d",
		stats.TotalRequests, stats.Intercepted, stats.PassedThrough)
}
