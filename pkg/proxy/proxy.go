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
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/auditlog"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/certificate"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/certinit"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/metrics"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/notify"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/platform"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/platformforward"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/detector"
	"golang.org/x/time/rate"
	"net/http/pprof"
)

// Operating modes
const (
	ModeMonitor = config.ModeMonitor
	ModeBlock   = config.ModeBlock
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

	// Graceful shutdown
	shutdownTimeout time.Duration

	// Rate limiting
	rateLimiter *rate.Limiter

	// Audit logging
	auditLog    *auditlog.Logger
	auditLogEnc *auditlog.EncryptedLogger // encrypted audit logger (if enabled)

	// Anonymized metrics
	metricsCollector *metrics.Collector

	// Platform forwarding
	forwarder *platformforward.Forwarder

	// Desktop notifications (daemon mode)
	notifier *notify.Notifier

	// pprof debug server
	pprofServer *http.Server
	pprofToken  string // CRITICAL-4: auth token for pprof

	// HIGH-7/MEDIUM-6: shared transport for outbound requests (explicit TLS config)
	sharedTransport *http.Transport

	// H3: API authentication token (empty = no auth, for backward compat)
	apiAuthToken string
}

// ProxyStats tracks interception statistics.
type ProxyStats struct {
	TotalRequests   int64     `json:"total_requests"`
	Intercepted     int64     `json:"intercepted"`
	PassedThrough   int64     `json:"passed_through"`
	Detections      int64     `json:"detections"`
	BlockedRequests int64     `json:"blocked_requests"`
	MLDetections    int64     `json:"ml_detections"`
	Mode            string    `json:"mode"`
	StartTime       time.Time `json:"start_time"`

	// Detection breakdown by category (for Lens integration)
	CategoryCounts    map[string]int64 `json:"category_counts,omitempty"`
	LastDetectionTime time.Time        `json:"last_detection_time,omitempty"`
	PIICategories     []string         `json:"pii_categories,omitempty"`

	// Latency tracking (for Lens integration)
	TotalLatencyMs int64   `json:"-"` // Sum of all detection latencies
	LatencySamples int64   `json:"-"` // Number of latency samples
	AvgLatencyMs   float64 `json:"avg_latency_ms,omitempty"`
}

// New creates a new Proxy with the given configuration.
func New(cfg *config.Config) (*Proxy, error) {
	// Rate limiter from config (default 10000 for perf testing)
	rateLimit := cfg.RateLimitRPS
	if rateLimit <= 0 {
		rateLimit = 30 // safe default
	}

	p := &Proxy{
		cfg:             cfg,
		targets:         make(map[string]bool),
		shutdownTimeout: 15 * time.Second,
		rateLimiter:     rate.NewLimiter(rate.Limit(rateLimit), rateLimit),
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

	// CRITICAL-2 FIX: Load the file-based CA (from certinit) into the manager
	// instead of generating a separate in-memory CA. The user installs the
	// file-based CA in their trust store, so MITM certs must be signed by it.
	p.certMgr = certificate.NewManager()
	if err := p.certMgr.LoadCAFromFiles(result.CACertPath, result.CAKeyPath); err != nil {
		// Fallback: generate new self-signed CA (for first-run without files)
		log.Printf("rampart: warning: could not load CA from files (%v), generating new CA", err)
		if _, err := p.certMgr.GenerateSelfSigned(); err != nil {
			log.Printf("rampart: warning: could not generate in-memory CA: %v", err)
		}
	} else {
		log.Printf("rampart: loaded CA from %s for MITM certificate signing", result.CACertPath)
	}

	// HIGH-7/MEDIUM-6: create a shared transport with explicit TLS config
	p.sharedTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// CRITICAL-4: generate a random pprof auth token if pprof is enabled
	if cfg.PprofAddr != "" {
		p.pprofToken = generatePprofToken()
	}

	// H3: set API auth token if configured
	// For now, use a random token printed at startup (if pprof is enabled)
	// In production, this should be configurable via flag or config

	// Initialize audit logger (best-effort, don't fail if audit log can't be created)
	auditLog, err := auditlog.New()
	if err != nil {
		log.Printf("rampart: warning: audit log disabled: %v", err)
		// Continue without audit logging — detection still works
	}
	p.auditLog = auditLog

	// Initialize encrypted audit logger (if passphrase provided)
	if cfg.AuditKeyPassphrase != "" {
		auditLogEnc, err := auditlog.NewEncryptedLogger(cfg.AuditKeyPassphrase)
		if err != nil {
			log.Printf("rampart: warning: encrypted audit log disabled: %v", err)
		} else {
			p.auditLogEnc = auditLogEnc
			log.Printf("rampart: encrypted audit logging enabled")
		}
	}

	// Initialize anonymized metrics collector (opt-in)
	if cfg.AnonymizedMetrics {
		endpoint := cfg.MetricsEndpoint
		if endpoint == "" {
			endpoint = metrics.DefaultMetricsEndpoint
		}
		p.metricsCollector = metrics.NewCollector(true, endpoint)
		log.Printf("rampart: anonymized metrics enabled (endpoint: %s)", endpoint)
	}

	// Initialize platform forwarder (opt-in, requires platform_url in config)
	if cfg.PlatformKey != "" {
		p.forwarder = platformforward.NewWithAPIKey(cfg.PlatformURL, cfg.PlatformKey)
	} else {
		p.forwarder = platformforward.New(cfg.PlatformURL)
	}

	// Initialize desktop notifier (used in daemon mode)
	if cfg.DaemonMode {
		p.notifier = notify.New("")
		log.Printf("rampart: desktop notifications enabled (daemon mode)")
	}

	return p, nil
}

// certDir returns the directory for storing certificates.
func certDir() string {
	return platform.ConfigDir()
}

// Start begins listening for HTTPS connections.
func (p *Proxy) Start(ctx context.Context) error {
	// CRITICAL-3 FIX: bind to localhost by default, not 0.0.0.0
	// This prevents the proxy from being used as an open proxy by
	// network-adjacent attackers. Users who need remote access should
	// use a reverse proxy or SSH tunnel.
	bindAddr := "127.0.0.1"
	addr := fmt.Sprintf("%s:%d", bindAddr, p.cfg.ProxyPort)
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
	modeLabel := "MONITOR"
	if p.cfg.Mode == ModeBlock {
		modeLabel = "BLOCK"
	}
	fmt.Printf("rampart: Detection engine ready (153 regex patterns + ML) — mode: %s\n", modeLabel)

	// Start pprof debug server if configured
	if p.cfg.PprofAddr != "" {
		// CRITICAL-4 FIX: wrap pprof with token-based authentication
		// and bind to localhost only
		pprofAddr := p.cfg.PprofAddr
		// Ensure localhost binding
		if strings.HasPrefix(pprofAddr, ":") {
			pprofAddr = "127.0.0.1" + pprofAddr
		}
		pprofMux := http.NewServeMux()
		pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		// Wrap with auth middleware
		authMux := http.NewServeMux()
		authMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// Check for token in Authorization header or query param
			token := r.Header.Get("X-Pprof-Token")
			if token == "" {
				token = r.URL.Query().Get("token")
			}
			if subtle.ConstantTimeCompare([]byte(token), []byte(p.pprofToken)) != 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("Unauthorized — pprof requires X-Pprof-Token header or ?token= query param\n"))
				return
			}
			pprofMux.ServeHTTP(w, r)
		})
		p.pprofServer = &http.Server{Addr: pprofAddr, Handler: authMux}
		go func() {
			log.Printf("rampart: pprof debug server listening on %s (auth token: %s)", pprofAddr, p.pprofToken)
			if err := p.pprofServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("rampart: pprof server error: %v", err)
			}
		}()
	}

	// Graceful shutdown: drain in-flight connections, then close
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), p.shutdownTimeout)
		defer cancel()
		log.Printf("rampart: shutting down, draining connections for up to %v...", p.shutdownTimeout)
		if err := p.server.Shutdown(shutdownCtx); err != nil {
			log.Printf("rampart: shutdown error: %v", err)
			_ = p.server.Close()
		}
		log.Printf("rampart: shutdown complete")
	}()

	if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}

// Shutdown gracefully stops the proxy, draining in-flight connections.
func (p *Proxy) Shutdown() {
	// Close audit log first (flush pending entries)
	if p.auditLog != nil {
		if err := p.auditLog.Close(); err != nil {
			log.Printf("rampart: audit log close: %v", err)
		}
	}

	// Close encrypted audit log (if enabled)
	if p.auditLogEnc != nil {
		if err := p.auditLogEnc.Close(); err != nil {
			log.Printf("rampart: encrypted audit log close: %v", err)
		}
	}

	// Flush and close metrics collector (if enabled)
	if p.metricsCollector != nil {
		p.metricsCollector.Flush()
		if err := p.metricsCollector.Close(); err != nil {
			log.Printf("rampart: metrics collector close: %v", err)
		}
	}

	// Shut down pprof debug server
	if p.pprofServer != nil {
		pprofCtx, pprofCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer pprofCancel()
		if err := p.pprofServer.Shutdown(pprofCtx); err != nil {
			log.Printf("rampart: pprof shutdown error: %v", err)
		}
	}
	if p.server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), p.shutdownTimeout)
		defer cancel()
		if err := p.server.Shutdown(shutdownCtx); err != nil {
			log.Printf("rampart: forced shutdown: %v", err)
			_ = p.server.Close()
		}
	}
}

// GetStats returns current proxy statistics.
func (p *Proxy) GetStats() ProxyStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s := p.stats
	s.Mode = p.cfg.Mode
	return s
}

// ReloadConfig reloads the configuration from disk and updates the proxy.
// Called on SIGHUP for hot-reload without restarting.
func (p *Proxy) ReloadConfig(cfg *config.Config) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cfg = cfg
	p.targets = make(map[string]bool)
	for _, t := range cfg.Targets {
		p.targets[t.Domain] = true
	}

	log.Printf("rampart: configuration reloaded — %d target domains", len(cfg.Targets))
}

// auditLogEntry writes a detection event to the audit log.
// Only metadata is stored — no prompt text, no PII values, no credentials.
// Detection results used for blocking decisions use full values (those are
// sent to the proxy user, not persisted), but what gets written to the
// audit log is redacted.
func (p *Proxy) auditLogEntry(direction, host, path string, result *detector.Summary) {
	// Determine highest severity for metrics
	highestSeverity := "low"
	severityOrder := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

	categories := make([]string, 0, len(result.Results))
	severities := make([]string, 0, len(result.Results))
	rules := make([]string, 0, len(result.Results))
	hasRedacted := false
	for _, r := range result.Results {
		categories = append(categories, r.Category)
		severities = append(severities, r.Severity)
		rules = append(rules, r.Rule)
		if auditlog.RedactText(r) != r.Text {
			hasRedacted = true
		}
		// Track highest severity
		if severityOrder[r.Severity] > severityOrder[highestSeverity] {
			highestSeverity = r.Severity
		}
	}

	entry := auditlog.Entry{
		Direction:     direction,
		Host:          host,
		Path:          path,
		TotalDets:     result.TotalDetections,
		Blocked:       result.Blocked,
		Redacted:      hasRedacted,
		PIICategories: result.PIICategories,
		SecretTypes:   result.SecretTypes,
		MLScore:       result.MLScore,
		Categories:    categories,
		Severities:    severities,
		Rules:         rules,
	}

	// Write to regular audit log
	if p.auditLog != nil {
		if err := p.auditLog.Log(entry); err != nil {
			log.Printf("rampart: audit log write failed: %v", err)
		}
	}

	// Write to encrypted audit log (if enabled)
	if p.auditLogEnc != nil {
		if err := p.auditLogEnc.Log(entry); err != nil {
			log.Printf("rampart: encrypted audit log write failed: %v", err)
		}
	}

	// Record anonymized metric (if enabled)
	if p.metricsCollector != nil && len(categories) > 0 {
		// Record metric for each detection category
		for _, category := range categories {
			p.metricsCollector.RecordDetection(host, category, highestSeverity, result.Blocked)
		}
	}

	// Track per-category counts and last detection time for Lens stats
	p.mu.Lock()
	if p.stats.CategoryCounts == nil {
		p.stats.CategoryCounts = make(map[string]int64)
	}
	for _, category := range categories {
		p.stats.CategoryCounts[category]++
	}
	p.stats.LastDetectionTime = time.Now()
	if len(result.PIICategories) > 0 {
		p.stats.PIICategories = result.PIICategories
	}
	p.mu.Unlock()
}

// forwardEntry sends detection metadata to AegisGate Platform.
// Only metadata is sent — never prompt text, PII values, or credentials.
// Forwarding is opt-in (requires platform_url in config).
func (p *Proxy) forwardEntry(direction, host, path string, result *detector.Summary) {
	if p.forwarder == nil || !p.forwarder.Enabled() {
		return
	}

	categories := make([]string, 0, len(result.Results))
	severities := make([]string, 0, len(result.Results))
	rules := make([]string, 0, len(result.Results))
	hasRedacted := false
	for _, r := range result.Results {
		categories = append(categories, r.Category)
		severities = append(severities, r.Severity)
		rules = append(rules, r.Rule)
		if auditlog.RedactText(r) != r.Text {
			hasRedacted = true
		}
	}

	entry := auditlog.Entry{
		Direction:     direction,
		Host:          host,
		Path:          path,
		TotalDets:     result.TotalDetections,
		Blocked:       result.Blocked,
		Redacted:      hasRedacted,
		PIICategories: result.PIICategories,
		SecretTypes:   result.SecretTypes,
		MLScore:       result.MLScore,
		Categories:    categories,
		Severities:    severities,
		Rules:         rules,
	}

	p.forwarder.Forward(entry)
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
	if r.Method == http.MethodGet && r.URL.Path == "/health" {
		p.HandleHealthAPI(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/ready" {
		p.HandleReadyAPI(w, r)
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

// isBlockedAddress checks if a host is a private/loopback/link-local address
// that should not be tunneled to (SSRF protection).
func isBlockedAddress(host string) bool {
	// Parse as IP first
	if ip := net.ParseIP(host); ip != nil {
		return isBlockedIP(ip)
	}

	// Resolve hostname and check all resulting IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		return false // Can't resolve — allow but it will fail at connect
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return true
		}
	}
	return false
}

// isBlockedIP returns true for loopback, private, link-local, and unspecified IPs.
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	// Block AWS/cloud metadata endpoint 169.254.169.254
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	return false
}

// generatePprofToken generates a random 32-byte hex token for pprof auth.
func generatePprofToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// isTargetDomain checks if a host matches any of our target domains.
// HIGH-1 FIX: acquire RLock to prevent concurrent map read/write panic
// when ReloadConfig writes to p.targets simultaneously.
func (p *Proxy) isTargetDomain(host string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

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
// CRITICAL-3 FIX: validate destination to prevent SSRF — block connections
// to private/loopback/link-local addresses.
func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.URL.Host)
	if err != nil {
		// No port specified, try :443 for HTTPS
		host = r.URL.Host
		port = "443"
	}

	// Block connections to private/loopback/link-local addresses
	if isBlockedAddress(host) {
		http.Error(w, "tunnel blocked: destination is a private/internal address", http.StatusForbidden)
		return
	}

	destConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		http.Error(w, "tunnel connection failed", http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "tunnel not supported", http.StatusInternalServerError)
		return
	}

	// Send HTTP 200 Connection Established to client before hijacking
	w.WriteHeader(http.StatusOK)

	hijackedConn, _, err := hijacker.Hijack()
	if err != nil {
		_ = destConn.Close()
		return
	}

	// Bidirectional copy — close both sides when done
	go func() {
		defer hijackedConn.Close()
		defer destConn.Close()
		_, _ = io.Copy(destConn, hijackedConn)
	}()
	go func() {
		_, _ = io.Copy(hijackedConn, destConn)
	}()
}

// interceptHTTPS performs MITM on target domain traffic:
// 1. Send 200 Connection Established to the client CONNECT request
// 2. Hijack the connection
// 3. Wrap with TLS using our generated per-domain certificate
// 4. Read the decrypted HTTP request
// 5. Run detection on request body
// 6. Forward to the real server
// 7. Run detection on response body
// 8. Write response back to client through TLS
func (p *Proxy) interceptHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()

	// Generate a MITM certificate for this domain on the fly
	mitmCert, err := p.certMgr.GenerateProxyCertificate(host)
	if err != nil {
		// HIGH-2 FIX: do NOT fall back to pass-through tunnel for target domains
		// (that would bypass all detection). Instead, return an error to the client.
		log.Printf("rampart: error generating MITM cert for target domain: %v", err)
		http.Error(w, "MITM certificate generation failed — request blocked to prevent detection bypass", http.StatusServiceUnavailable)
		return
	}

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("rampart: hijacking not supported, falling back to tunnel for %s", host)
		p.tunnel(w, r) // Fall back to pass-through
		return
	}

	// Send 200 Connection Established before hijacking
	w.WriteHeader(http.StatusOK)

	hijackedConn, _, err := hijacker.Hijack()
	if err != nil {
		// LOW-4 FIX: can't tunnel after WriteHeader(200) — just close
		log.Printf("rampart: hijack failed for target domain: %v", err)
		_ = hijackedConn.Close()
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

	// Wrap the hijacked connection with TLS (we act as TLS server to the client)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		// HIGH-5 FIX: restrict to AEAD cipher suites only
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	tlsConn := tls.Server(hijackedConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("rampart: TLS handshake failed for %s: %v", host, err)
		_ = hijackedConn.Close()
		return
	}
	defer tlsConn.Close()

	// Read the client's HTTP request through the TLS connection
	reader := bufio.NewReader(tlsConn)
	clientReq, err := http.ReadRequest(reader)
	if err != nil {
		// Client closed connection or sent invalid request — not a fatal error
		return
	}

	// Read request body for scanning
	// MEDIUM-4 FIX: limit body size to prevent OOM
	const maxBodySize = 100 << 20 // 100 MB
	var bodyBytes []byte
	if clientReq.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(clientReq.Body, maxBodySize))
		_ = clientReq.Body.Close()
	}

	// Run detection on request body (outbound = user prompt)
	if len(bodyBytes) > 0 {
		result := p.scanAndAlert("request", host, clientReq.URL.Path, bodyBytes)

		// Block mode: check if the request should be blocked
		if result != nil && result.TotalDetections > 0 {
			if shouldBlock, reason := p.shouldBlock(result); shouldBlock {
				p.mu.Lock()
				p.stats.BlockedRequests++
				p.mu.Unlock()
				// Write block response back to client through TLS
				blockResp := p.formatBlockHTTPResponse("request", host, clientReq.URL.Path, result, reason)
				_, _ = fmt.Fprintf(tlsConn, "HTTP/1.1 %d %s\r\n", p.cfg.Block.StatusCode, http.StatusText(p.cfg.Block.StatusCode))
				_, _ = fmt.Fprintf(tlsConn, "Content-Type: application/json\r\n")
				_, _ = fmt.Fprintf(tlsConn, "X-Rampart-Blocked: true\r\n")
				_, _ = fmt.Fprintf(tlsConn, "Content-Length: %d\r\n", len(blockResp))
				_, _ = fmt.Fprintf(tlsConn, "Connection: close\r\n\r\n")
				_, _ = tlsConn.Write(blockResp)
				return
			}
		}
	}

	// Reconstruct the request body for forwarding
	clientReq.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	clientReq.URL.Scheme = "https"
	clientReq.URL.Host = host
	if clientReq.Host == "" {
		clientReq.Host = host
	}

	// HIGH-7/MEDIUM-6 FIX: use shared transport (explicit TLS config, connection reuse)
	resp, err := p.sharedTransport.RoundTrip(clientReq)
	if err != nil {
		// MEDIUM-5 FIX: don't log the hostname
		log.Printf("rampart: error forwarding to target domain: %v", err)
		return
	}
	defer resp.Body.Close()

	// Read response body for scanning
	// MEDIUM-4 FIX: limit body size to prevent OOM
	var respBody []byte
	if resp.Body != nil {
		respBody, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	}

	// Run detection on response body (inbound = AI response)
	if len(respBody) > 0 {
		result := p.scanAndAlert("response", host, clientReq.URL.Path, respBody)

		// Block mode: check if the response should be blocked
		if result != nil && result.TotalDetections > 0 {
			if shouldBlock, reason := p.shouldBlock(result); shouldBlock {
				p.mu.Lock()
				p.stats.BlockedRequests++
				p.mu.Unlock()
				blockResp := p.formatBlockHTTPResponse("response", host, clientReq.URL.Path, result, reason)
				_, _ = fmt.Fprintf(tlsConn, "HTTP/1.1 %d %s\r\n", p.cfg.Block.StatusCode, http.StatusText(p.cfg.Block.StatusCode))
				_, _ = fmt.Fprintf(tlsConn, "Content-Type: application/json\r\n")
				_, _ = fmt.Fprintf(tlsConn, "X-Rampart-Blocked: true\r\n")
				_, _ = fmt.Fprintf(tlsConn, "Content-Length: %d\r\n", len(blockResp))
				_, _ = fmt.Fprintf(tlsConn, "Connection: close\r\n\r\n")
				_, _ = tlsConn.Write(blockResp)
				return
			}
		}
	}

	// Write the response back to the client through the TLS connection
	resp.Body = io.NopCloser(strings.NewReader(string(respBody)))
	_ = resp.Write(tlsConn)
}

// handleHTTP handles plain HTTP requests (rare for AI APIs).
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	if host == "" {
		host = r.Host
	}

	isTarget := p.isTargetDomain(host)

	// Read request body
	// MEDIUM-4 FIX: limit body size
	const maxHTTPBodySize = 100 << 20 // 100 MB
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, maxHTTPBodySize))
		_ = r.Body.Close()
	}

	if isTarget && len(bodyBytes) > 0 {
		p.mu.Lock()
		p.stats.Intercepted++
		p.mu.Unlock()
		result := p.scanAndAlert("request", host, r.URL.Path, bodyBytes)

		// Block mode: check if the request should be blocked
		if result != nil && result.TotalDetections > 0 {
			if shouldBlock, reason := p.shouldBlock(result); shouldBlock {
				p.blockResponse(w, "request", host, r.URL.Path, result, reason)
				return
			}
		}
	}

	// Forward the request
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	// HIGH-7 FIX: use shared transport with explicit TLS config
	resp, err := p.sharedTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, "forward failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body
	// MEDIUM-4 FIX: limit body size
	var respBody []byte
	if resp.Body != nil {
		respBody, _ = io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodySize))
	}

	if isTarget && len(respBody) > 0 {
		result := p.scanAndAlert("response", host, r.URL.Path, respBody)

		// Block mode: check if the response should be blocked
		if result != nil && result.TotalDetections > 0 {
			if shouldBlock, reason := p.shouldBlock(result); shouldBlock {
				p.blockResponse(w, "response", host, r.URL.Path, result, reason)
				return
			}
		}
	}

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// shouldBlock determines if a detection result should be blocked based on
// the current mode and block configuration. Returns true if the request/response
// should be blocked, and the reason if applicable.
func (p *Proxy) shouldBlock(result *detector.Summary) (bool, string) {
	// Monitor mode: never block
	if p.cfg.Mode != ModeBlock {
		return false, ""
	}

	// No detections: nothing to block
	if result.TotalDetections == 0 {
		return false, ""
	}

	blockCfg := p.cfg.Block

	// Check each detection against threshold and category filters
	for _, r := range result.Results {
		// Severity threshold check
		if !meetsSeverityThreshold(r.Severity, blockCfg.Threshold) {
			continue
		}

		// Category filter check (empty = all categories)
		if len(blockCfg.Categories) > 0 && !containsCategory(blockCfg.Categories, r.Category) {
			continue
		}

		// At least one detection meets both threshold and category criteria
		// MEDIUM-3 FIX: don't include raw detection text in block reason
		return true, fmt.Sprintf("%s: [redacted]", r.Category)
	}

	return false, ""
}

// meetsSeverityThreshold checks if a severity meets the blocking threshold.
func meetsSeverityThreshold(severity, threshold string) bool {
	severityLevels := map[string]int{
		config.SeverityCritical: 4,
		config.SeverityHigh:     3,
		config.SeverityMedium:   2,
		config.SeverityLow:      1,
	}
	sevLevel, ok := severityLevels[severity]
	if !ok {
		sevLevel = 0
	}
	thrLevel, ok := severityLevels[threshold]
	if !ok {
		thrLevel = 3 // default: high
	}
	return sevLevel >= thrLevel
}

// containsCategory checks if a category is in the allowed list.
func containsCategory(categories []string, cat string) bool {
	for _, c := range categories {
		if c == cat {
			return true
		}
	}
	return false
}

// blockResponse writes an HTTP response that blocks the request/response.
// In block mode, Rampart returns a structured JSON response explaining why.
func (p *Proxy) blockResponse(w http.ResponseWriter, direction, host, path string, result *detector.Summary, blockReason string) {
	p.mu.Lock()
	p.stats.BlockedRequests++
	p.mu.Unlock()

	statusCode := p.cfg.Block.StatusCode
	if statusCode == 0 {
		statusCode = 403
	}

	blockMsg := p.cfg.Block.Message
	if blockMsg == "" {
		blockMsg = "Request blocked by AegisGate Rampart"
	}

	// Build the block response body
	type BlockResult struct {
		Category   string  `json:"category"`
		Severity   string  `json:"severity"`
		Rule       string  `json:"rule"`
		Text       string  `json:"text,omitempty"`
		Confidence float64 `json:"confidence"`
	}

	type BlockDetail struct {
		Direction string        `json:"direction"`
		Host      string        `json:"host"`
		Path      string        `json:"path,omitempty"`
		Blocked   bool          `json:"blocked"`
		Reason    string        `json:"reason"`
		Severity  string        `json:"severity"`
		Message   string        `json:"message"`
		Results   []BlockResult `json:"results,omitempty"`
	}

	detail := BlockDetail{
		Direction: direction,
		Host:      host,
		Path:      path,
		Blocked:   true,
		Reason:    blockReason,
		Message:   blockMsg,
	}

	// Include detection details if configured
	if p.cfg.Block.IncludeDetections {
		detail.Results = make([]BlockResult, 0, len(result.Results))
		for _, r := range result.Results {
			// MEDIUM-3 FIX: redact sensitive text in block responses
			detail.Results = append(detail.Results, BlockResult{
				Category:   r.Category,
				Severity:   r.Severity,
				Rule:       r.Rule,
				Text:       redactDetectionText(r.Text),
				Confidence: r.Confidence,
			})
		}
	}

	// Determine overall severity from the highest-severity detection
	highestSev := "low"
	for _, r := range result.Results {
		if meetsSeverityThreshold(r.Severity, highestSev) {
			highestSev = r.Severity
		}
	}
	detail.Severity = highestSev

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Rampart-Blocked", "true")
	w.Header().Set("X-Rampart-Severity", highestSev)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(detail)
}

// scanAndAlert runs detection on a body and alerts the user.
func (p *Proxy) scanAndAlert(direction, host, path string, body []byte) *detector.Summary {
	result, err := p.detector.Detect(string(body))
	if err != nil {
		log.Printf("rampart: detection error: %v", err)
		return result
	}

	if result.TotalDetections == 0 {
		return result
	}

	p.mu.Lock()
	p.stats.Detections++
	if result.MLScore > 0 {
		p.stats.MLDetections++
	}
	// Track latency for Lens integration
	if result.LatencyMs > 0 {
		p.stats.TotalLatencyMs += result.LatencyMs
		p.stats.LatencySamples++
		if p.stats.LatencySamples > 0 {
			p.stats.AvgLatencyMs = float64(p.stats.TotalLatencyMs) / float64(p.stats.LatencySamples)
		}
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

	// Write to audit log (best-effort, metadata only, no prompt text)
	p.auditLogEntry(direction, host, path, result)

	// Forward to Platform (opt-in, metadata only, async)
	p.forwardEntry(direction, host, path, result)

	return result
}

// ANSI color codes for terminal output.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// printDetection formats and prints detection results to the terminal.
// Uses color-coded output: red=critical/high, yellow=medium, green=low.
func (p *Proxy) printDetection(direction, host, path string, result *detector.Summary) {
	// Header with severity-appropriate coloring
	severityColor := colorRed
	severityIcon := "⚠️"
	if p.cfg.Mode == ModeBlock {
		severityColor = colorRed
		severityIcon = "🚫"
	} else if result.TotalDetections == 1 {
		severityColor = colorYellow
		severityIcon = "⚠️"
	}

	modeTag := ""
	if p.cfg.Mode == ModeBlock {
		modeTag = colorRed + " [BLOCKED]" + colorReset
	}

	fmt.Printf("\n%s%s %sDETECTION: %s %s%s%s%s\n",
		severityColor, severityIcon, colorBold,
		direction, colorCyan, host, colorReset, modeTag)

	if path != "" && path != "/" {
		fmt.Printf("   %s%s%s\n", colorDim, path, colorReset)
	}

	// Summary line
	fmt.Printf("   Detections: %s%d%s | Blocked: %s%v%s",
		colorBold, result.TotalDetections, colorReset,
		boolColor(result.Blocked), result.Blocked, colorReset)

	if len(result.PIICategories) > 0 {
		fmt.Printf(" | PII: %s%v%s", colorYellow, result.PIICategories, colorReset)
	}
	if len(result.SecretTypes) > 0 {
		fmt.Printf(" | Secrets: %s%v%s", colorRed, result.SecretTypes, colorReset)
	}
	if result.MLScore > 0 {
		mlColor := colorGreen
		if result.MLScore >= 0.7 {
			mlColor = colorRed
		} else if result.MLScore >= 0.4 {
			mlColor = colorYellow
		}
		fmt.Printf(" | ML: %s%.3f%s", mlColor, result.MLScore, colorReset)
	}
	fmt.Println()

	// Individual detection results
	for _, r := range result.Results {
		dColor, emoji := severityColorAndEmoji(r.Severity)
		// MEDIUM-3 FIX: redact detection text in terminal output
		fmt.Printf("   %s %s[%s]%s %s: %s\n", emoji, dColor, r.Severity, colorReset, r.Category, redactDetectionText(r.Text))
	}
	fmt.Println()
}

// severityColorAndEmoji returns the ANSI color and emoji for a severity level.
func severityColorAndEmoji(severity string) (string, string) {
	switch severity {
	case "critical":
		return colorRed, "🔴"
	case "high":
		return colorRed, "🔴"
	case "medium":
		return colorYellow, "🟡"
	case "low":
		return colorGreen, "🟢"
	default:
		return colorCyan, "⚪"
	}
}

// boolColor returns a color string for boolean values.
func boolColor(b bool) string {
	if b {
		return colorRed
	}
	return colorGreen
}

// notifyDesktop sends a desktop notification (daemon mode).
// Uses the internal/notify package for cross-platform OS-native notifications.
// If no notifier is configured (non-daemon mode), falls back to logging.
func (p *Proxy) notifyDesktop(direction, host string, result *detector.Summary) {
	if p.notifier == nil {
		// No notifier configured — log to stderr
		log.Printf("rampart: [%s] %s — %d detections", direction, host, result.TotalDetections)
		return
	}

	// Build category list from results
	var categories []string
	for _, r := range result.Results {
		categories = append(categories, r.Category)
	}

	// Send the notification (best-effort, don't block on failures)
	if err := p.notifier.SendDetection(host, result.TotalDetections, categories); err != nil {
		// Notification failed — log as fallback, don't disrupt proxy flow
		log.Printf("rampart: [%s] %s — %d detections (notification failed: %v)",
			direction, host, result.TotalDetections, err)
	}
}

// formatBlockHTTPResponse creates a JSON block response body for MITM responses.
func (p *Proxy) formatBlockHTTPResponse(direction, host, path string, result *detector.Summary, blockReason string) []byte {
	blockMsg := p.cfg.Block.Message
	if blockMsg == "" {
		blockMsg = "Request blocked by AegisGate Rampart"
	}

	type BlockResult struct {
		Category   string  `json:"category"`
		Severity   string  `json:"severity"`
		Rule       string  `json:"rule"`
		Text       string  `json:"text,omitempty"`
		Confidence float64 `json:"confidence"`
	}

	type BlockDetail struct {
		Direction string        `json:"direction"`
		Host      string        `json:"host"`
		Path      string        `json:"path,omitempty"`
		Blocked   bool          `json:"blocked"`
		Reason    string        `json:"reason"`
		Severity  string        `json:"severity"`
		Message   string        `json:"message"`
		Results   []BlockResult `json:"results,omitempty"`
	}

	detail := BlockDetail{
		Direction: direction,
		Host:      host,
		Path:      path,
		Blocked:   true,
		Reason:    blockReason,
		Message:   blockMsg,
	}

	if p.cfg.Block.IncludeDetections {
		detail.Results = make([]BlockResult, 0, len(result.Results))
		for _, r := range result.Results {
			// MEDIUM-3 FIX: redact sensitive text in block responses
			detail.Results = append(detail.Results, BlockResult{
				Category:   r.Category,
				Severity:   r.Severity,
				Rule:       r.Rule,
				Text:       redactDetectionText(r.Text),
				Confidence: r.Confidence,
			})
		}
	}

	// Determine overall severity
	highestSev := "low"
	for _, r := range result.Results {
		if meetsSeverityThreshold(r.Severity, highestSev) {
			highestSev = r.Severity
		}
	}
	detail.Severity = highestSev

	data, _ := json.Marshal(detail)
	return data
}

// redactDetectionText masks sensitive detection text for safe display/logging.
func redactDetectionText(text string) string {
	if len(text) <= 4 {
		return "[REDACTED]"
	}
	return text[:2] + "***" + text[len(text)-2:]
}

// HandleDetectAPI serves the /detect HTTP endpoint for IDE extensions.
// POST /detect { "text": "..." } → detection results
func (p *Proxy) HandleDetectAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit: protect against abuse from IDE extensions
	if !p.rateLimiter.Allow() {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Request body size limit: 10MB max to prevent compute abuse
	const maxBodySize = 10 << 20 // 10 MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

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
		if result.MLScore > 0 {
			p.stats.MLDetections++
		}
		p.mu.Unlock()

		// Block mode: return block response instead of detection result
		if shouldBlock, reason := p.shouldBlock(result); shouldBlock {
			p.blockResponse(w, "request", "", "/detect", result, reason)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// HandleStatsAPI serves the /stats HTTP endpoint.
// GET /stats → proxy statistics
func (p *Proxy) HandleStatsAPI(w http.ResponseWriter, r *http.Request) {
	// Rate limit: protect against polling abuse
	if !p.rateLimiter.Allow() {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p.GetStats())
}

// HandleHealthAPI serves the /health endpoint for liveness probes.
// GET /health → {"status":"ok"}
func (p *Proxy) HandleHealthAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// HandleReadyAPI serves the /ready endpoint for readiness probes.
// GET /ready → {"status":"ready","detector":true} if the detector is initialized.
func (p *Proxy) HandleReadyAPI(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	detectorReady := p.detector != nil
	p.mu.RUnlock()

	status := "ready"
	if !detectorReady {
		status = "not_ready"
	}

	w.Header().Set("Content-Type", "application/json")
	code := http.StatusOK
	if !detectorReady {
		code = http.StatusServiceUnavailable
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    status,
		"detector":  detectorReady,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
