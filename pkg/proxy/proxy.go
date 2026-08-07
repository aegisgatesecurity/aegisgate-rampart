// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - HTTPS MITM Proxy
// =========================================================================
//
// Local HTTPS proxy that intercepts AI API traffic for detection.
// MITM-terminates for target domains only; passes through all other traffic.
//
// Architecture:
//   1. Client → Rampart proxy → MITM for target domains (scan + forward)
//   2. Client → Rampart proxy → transparent pass-through for everything else
//   3. First run: generates local CA cert, prompts user to trust it
//
// Privacy (12 non-negotiables):
//   - No prompt text stored or sent anywhere
//   - No PII stored or forwarded
//   - Detection happens locally, results are for the user only
//   - Telemetry to Platform is opt-in and sends only metadata (never content)
//
// =========================================================================

package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/certificate"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/certinit"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"
)

// Proxy is the local HTTPS interception proxy.
type Proxy struct {
	cfg      *config.Config
	detector *detector.Detector
	server   *http.Server
	certMgr  *certificate.Manager
	certInit *certinit.Result
	targets  map[string]bool // domain → intercept?
	mu       sync.RWMutex
	stats    ProxyStats
}

// ProxyStats tracks interception statistics.
type ProxyStats struct {
	TotalRequests   int64     `json:"total_requests"`
	Intercepted     int64     `json:"intercepted"`
	PassedThrough   int64     `json:"passed_through"`
	Detections      int64     `json:"detections"`
	BlockedRequests int64     `json:"blocked_requests"`
	MLDetections    int64     `json:"ml_detections"`
	StartTime       time.Time `json:"start_time"`
}

// New creates a new Proxy with the given configuration.
func New(cfg *config.Config) (*Proxy, error) {
	p := &Proxy{
		cfg:     cfg,
		targets: make(map[string]bool),
	}

	// Build target domain map
	for _, t := range cfg.Targets {
		p.targets[t.Domain] = true
	}

	// Initialize detector
	det, err := detector.New(detector.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("initializing detector: %w", err)
	}
	p.detector = det

	// Initialize CA certificate
	ciConfig := certinit.Config{
		CertDir:      certDir(),
		AutoGenerate: true,
		Hostnames:    []string{"localhost", "rampart.local"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(ciConfig)
	if err != nil {
		return nil, fmt.Errorf("certificate initialization: %w", err)
	}
	p.certInit = result

	if result.Generated {
		log.Printf("rampart: Generated new CA certificate at %s", result.CACertPath)
		log.Printf("rampart: Trust this CA cert in your browser/system to intercept HTTPS traffic")
	} else if result.Existing {
		log.Printf("rampart: Using existing CA certificate")
	}

	// Create certificate manager for dynamic MITM cert generation
	p.certMgr = certificate.NewManager()
	// Pre-generate the self-signed CA (certinit already wrote files, but we need in-memory)
	if _, err := p.certMgr.GenerateSelfSigned(); err != nil {
		log.Printf("rampart: warning: could not generate in-memory CA: %v", err)
	}

	return p, nil
}

// certDir returns the directory for storing certificates.
func certDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./certs"
	}
	return filepath.Join(home, ".config", "aegisgate-rampart")
}

// Start begins listening for HTTPS connections.
func (p *Proxy) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", p.cfg.ProxyPort)
	p.stats.StartTime = time.Now()

	// Create HTTP server with our handler
	p.server = &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(p.handleRequest),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}

	fmt.Printf("rampart: Listening on %s\n", addr)
	fmt.Printf("rampart: Intercepting %d AI API endpoints\n", len(p.cfg.Targets))
	fmt.Printf("rampart: Detection engine ready (153 regex patterns + ML)\n")

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		p.server.Close()
	}()

	if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}

// Shutdown gracefully stops the proxy.
func (p *Proxy) Shutdown() {
	if p.server != nil {
		p.server.Close()
	}
}

// GetStats returns current proxy statistics.
func (p *Proxy) GetStats() ProxyStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats
}

// handleRequest is the main HTTP/HTTPS proxy handler.
func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.stats.TotalRequests++
	p.mu.Unlock()

	// API endpoints (for IDE extensions and monitoring)
	if r.Method == http.MethodPost && r.URL.Path == "/detect" {
		p.HandleDetectAPI(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/stats" {
		p.HandleStatsAPI(w, r)
		return
	}

	// CONNECT method = HTTPS proxying
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
		return
	}

	// Plain HTTP = simple forward (rare for AI APIs)
	p.handleHTTP(w, r)
}

// handleCONNECT handles HTTPS CONNECT requests.
// For target domains: MITM-terminate, scan, forward.
// For all other domains: transparent tunnel.
func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()

	// Check if this is a target domain
	isTarget := p.isTargetDomain(host)

	if !isTarget {
		// Pass-through: tunnel without interception
		p.mu.Lock()
		p.stats.PassedThrough++
		p.mu.Unlock()
		p.tunnel(w, r)
		return
	}

	// Intercept: MITM-terminate, scan, forward
	p.mu.Lock()
	p.stats.Intercepted++
	p.mu.Unlock()
	p.interceptHTTPS(w, r)
}

// isTargetDomain checks if a host matches any of our target domains.
func (p *Proxy) isTargetDomain(host string) bool {
	// Exact match
	if p.targets[host] {
		return true
	}

	// Subdomain match (e.g., api.openai.com matches openai.com)
	parts := strings.Split(host, ".")
	for i := 0; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if p.targets[parent] {
			return true
		}
	}

	return false
}

// tunnel passes HTTPS traffic through without interception.
func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.URL.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "tunnel connection failed", http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "tunnel not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijackedConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	// Bidirectional copy
	go func() { io.Copy(destConn, hijackedConn) }()
	go func() { io.Copy(hijackedConn, destConn) }()
}

// interceptHTTPS performs MITM on target domain traffic:
// 1. Terminate TLS with our generated cert
// 2. Read the decrypted request body
// 3. Run detection
// 4. If clean: forward to real server
// 5. If threat detected: alert user (in foreground mode, print; in daemon mode, notify)
func (p *Proxy) interceptHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()

	// Generate a MITM certificate for this domain on the fly
	mitmCert, err := p.certMgr.GenerateProxyCertificate(host)
	if err != nil {
		log.Printf("rampart: error generating MITM cert for %s: %v", host, err)
		p.tunnel(w, r) // Fall back to pass-through
		return
	}

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.tunnel(w, r) // Fall back to pass-through
		return
	}

	w.WriteHeader(http.StatusOK)
	hijackedConn, _, err := hijacker.Hijack()
	if err != nil {
		p.tunnel(w, r) // Fall back to pass-through
		return
	}

	// Parse the MITM certificate into a tls.Certificate
	var tlsCert tls.Certificate
	switch key := mitmCert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		tlsCert = tls.Certificate{
			Certificate: [][]byte{mitmCert.Certificate.Raw},
			PrivateKey:  key,
		}
	default:
		// Fallback: use PEM bytes directly
		tlsCert, _ = tls.X509KeyPair(mitmCert.CertBytes, mitmCert.KeyBytes)
	}

	// Wrap the hijacked connection with TLS using our MITM cert
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	tlsConn := tls.Server(hijackedConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("rampart: TLS handshake failed for %s: %v", host, err)
		hijackedConn.Close()
		return
	}
	defer tlsConn.Close()

	// Read the client's request through the TLS connection
	reader := bufio.NewReader(tlsConn)
	clientReq, err := http.ReadRequest(reader)
	if err != nil {
		// Client closed connection or invalid request — not an error
		return
	}

	// Read request body for scanning
	var bodyBytes []byte
	if clientReq.Body != nil {
		bodyBytes, _ = io.ReadAll(clientReq.Body)
		clientReq.Body.Close()
	}

	// Run detection on request body (outbound = user prompt)
	if len(bodyBytes) > 0 {
		p.scanAndAlert("request", host, clientReq.URL.Path, bodyBytes)
	}

	// Forward the request to the real server
	clientReq.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	clientReq.URL.Scheme = "https"
	clientReq.URL.Host = host
	if clientReq.Host == "" {
		clientReq.Host = host
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	defer transport.CloseIdleConnections()

	resp, err := transport.RoundTrip(clientReq)
	if err != nil {
		log.Printf("rampart: error forwarding to %s: %v", host, err)
		return
	}
	defer resp.Body.Close()

	// Read response body for scanning
	var respBody []byte
	if resp.Body != nil {
		respBody, _ = io.ReadAll(resp.Body)
	}

	// Run detection on response body (inbound = AI response)
	if len(respBody) > 0 {
		p.scanAndAlert("response", host, clientReq.URL.Path, respBody)
	}

	// Write the response back to the client through the TLS connection
	resp.Body = io.NopCloser(strings.NewReader(string(respBody)))
	resp.Write(tlsConn)
}

// handleHTTP handles plain HTTP requests (rare for AI APIs).
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if host == "" {
		host = r.Host
	}

	isTarget := p.isTargetDomain(host)

	// Read request body
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}

	if isTarget && len(bodyBytes) > 0 {
		p.mu.Lock()
		p.stats.Intercepted++
		p.mu.Unlock()
		p.scanAndAlert("request", host, r.URL.Path, bodyBytes)
	}

	// Forward the request
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, "forward failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body
	var respBody []byte
	if resp.Body != nil {
		respBody, _ = io.ReadAll(resp.Body)
	}

	if isTarget && len(respBody) > 0 {
		p.scanAndAlert("response", host, r.URL.Path, respBody)
	}

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// scanAndAlert runs detection on a body and alerts the user.
func (p *Proxy) scanAndAlert(direction, host, path string, body []byte) {
	result, err := p.detector.Detect(string(body))
	if err != nil {
		log.Printf("rampart: detection error: %v", err)
		return
	}

	if result.TotalDetections == 0 {
		return
	}

	p.mu.Lock()
	p.stats.Detections++
	if result.Blocked {
		p.stats.BlockedRequests++
	}
	if result.MLScore > 0 {
		p.stats.MLDetections++
	}
	p.mu.Unlock()

	// Format detection results for user
	if p.cfg.DaemonMode {
		// Daemon mode: send desktop notification
		p.notifyDesktop(direction, host, result)
	} else {
		// Foreground mode: print to terminal
		p.printDetection(direction, host, path, result)
	}
}

// printDetection formats and prints detection results to the terminal.
func (p *Proxy) printDetection(direction, host, path string, result *detector.Summary) {
	fmt.Printf("\n⚠️  DETECTION: %s %s%s\n", direction, host, path)
	fmt.Printf("   Detections: %d | Blocked: %v", result.TotalDetections, result.Blocked)

	if len(result.PIICategories) > 0 {
		fmt.Printf(" | PII: %v", result.PIICategories)
	}
	if len(result.SecretTypes) > 0 {
		fmt.Printf(" | Secrets: %v", result.SecretTypes)
	}
	if result.MLScore > 0 {
		fmt.Printf(" | ML score: %.3f", result.MLScore)
	}
	fmt.Println()

	for _, r := range result.Results {
		emoji := "🔴"
		if r.Severity == "medium" {
			emoji = "🟡"
		} else if r.Severity == "low" {
			emoji = "🟢"
		}
		fmt.Printf("   %s [%s] %s: %s\n", emoji, r.Severity, r.Category, r.Text)
	}
	fmt.Println()
}

// notifyDesktop sends a desktop notification (daemon mode).
// TODO: Phase 2 — implement system tray notifications.
func (p *Proxy) notifyDesktop(direction, host string, result *detector.Summary) {
	// Phase 2 will use OS-native notifications (notify-send, osascript, etc.)
	// For now, log to stderr
	log.Printf("rampart: [%s] %s — %d detections", direction, host, result.TotalDetections)
}

// HandleDetectAPI serves the /detect HTTP endpoint for IDE extensions.
// POST /detect { "text": "..." } → detection results
func (p *Proxy) HandleDetectAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	result, err := p.detector.Detect(req.Text)
	if err != nil {
		http.Error(w, "detection failed", http.StatusInternalServerError)
		return
	}

	// Update stats for /detect API calls
	if result.TotalDetections > 0 {
		p.mu.Lock()
		p.stats.Detections++
		if result.Blocked {
			p.stats.BlockedRequests++
		}
		if result.MLScore > 0 {
			p.stats.MLDetections++
		}
		p.mu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// HandleStatsAPI serves the /stats HTTP endpoint.
// GET /stats → proxy statistics
func (p *Proxy) HandleStatsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p.GetStats())
}
