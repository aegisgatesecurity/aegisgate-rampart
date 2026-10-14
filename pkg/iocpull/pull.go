// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - IOC Pull Implementation
// =========================================================================

package iocpull

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------

// IOCEntry represents a single IOC fetched from Platform.
type IOCEntry struct {
	Fingerprint string    `json:"fingerprint"` // SHA-256 hash (may be prefixed with "sha256:")
	RuleID      string    `json:"rule_id"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	PeerCount   int       `json:"peer_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// IOCCache is a thread-safe local cache of pulled IOCs.
type IOCCache struct {
	mu      sync.RWMutex
	entries map[string]IOCEntry // keyed by fingerprint
	updated time.Time
}

// NewIOCCache returns an empty IOC cache.
func NewIOCCache() *IOCCache {
	return &IOCCache{
		entries: make(map[string]IOCEntry),
	}
}

// Store replaces all entries in the cache and records the update time.
func (c *IOCCache) Store(iocs []IOCEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]IOCEntry, len(iocs))
	for _, e := range iocs {
		c.entries[e.Fingerprint] = e
	}
	c.updated = now
}

// Get looks up an IOC by fingerprint. Returns the entry and true if found.
func (c *IOCCache) Get(fingerprint string) (IOCEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[fingerprint]
	return e, ok
}

// All returns a slice of all cached IOCs.
func (c *IOCCache) All() []IOCEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]IOCEntry, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e)
	}
	return out
}

// Size returns the number of cached IOCs.
func (c *IOCCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// UpdatedAt returns the time of the last successful store.
func (c *IOCCache) UpdatedAt() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.updated
}

// PullResult is the outcome of a Pull call.
type PullResult struct {
	IOCs      []IOCEntry
	FromCache bool
	UpdatedAt string
}

// iocResponse is the JSON envelope returned by Platform's IOC endpoint.
type iocResponse struct {
	APIVersion string     `json:"api_version"`
	IOCs       []IOCEntry `json:"iocs"`
	UpdatedAt  string     `json:"updated_at"`
}

// IOCPuller fetches IOC updates from AegisGate Platform.
type IOCPuller struct {
	url         string // Platform base URL
	apiKey      string // Bearer token
	client      *http.Client
	enabled     bool   // true if url is non-empty
	lastUpdated string // If-Modified-Since value
	nowFunc     func() time.Time
	version     string // Rampart version for User-Agent
	cache       *IOCCache
}

// -----------------------------------------------------------------------
// Constructors
// -----------------------------------------------------------------------

// New creates an IOCPuller. If url is empty, pulling is disabled and
// Rampart operates with local detections only.
func New(url string) *IOCPuller {
	return NewWithAPIKey(url, "", "")
}

// NewWithAPIKey creates an IOCPuller with API key authentication and
// a Rampart version string used for the User-Agent header.
func NewWithAPIKey(url, apiKey, version string) *IOCPuller {
	enabled := url != ""
	if enabled {
		log.Printf("rampart: IOC pull enabled → %s", maskURL(url))
	} else {
		log.Printf("rampart: IOC pull disabled (no platform_url configured)")
	}

	if version == "" {
		version = "unknown"
	}

	return &IOCPuller{
		url:     strings.TrimRight(url, "/"),
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 10 * time.Second},
		enabled: enabled,
		nowFunc: time.Now,
		version: version,
		cache:   NewIOCCache(),
	}
}

// -----------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------

// IsEnabled returns true if the puller has a non-empty Platform URL.
func (p *IOCPuller) IsEnabled() bool {
	return p.enabled
}

// Pull fetches the latest IOCs from Platform. On HTTP 304 the cache is
// served (FromCache=true). On 401 or 500 an error is returned.
func (p *IOCPuller) Pull() (*PullResult, error) {
	if !p.enabled {
		return nil, fmt.Errorf("iocpull: disabled (no platform_url configured)")
	}

	endpoint := p.url + "/api/v1/ioc/latest"

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("iocpull: request creation: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aegisgate-rampart/"+p.version)

	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	if p.lastUpdated != "" {
		req.Header.Set("If-Modified-Since", p.lastUpdated)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("iocpull: request: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		// No changes — serve from cache
		return &PullResult{
			IOCs:      p.cache.All(),
			FromCache: true,
			UpdatedAt: p.lastUpdated,
		}, nil

	case resp.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("iocpull: authentication failed (HTTP 401)")

	case resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("iocpull: forbidden (HTTP 403)")

	case resp.StatusCode >= 500:
		return nil, fmt.Errorf("iocpull: server error (HTTP %d)", resp.StatusCode)

	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("iocpull: unexpected status (HTTP %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // 16 MiB cap
	if err != nil {
		return nil, fmt.Errorf("iocpull: read body: %w", err)
	}

	var iocResp iocResponse
	if err := json.Unmarshal(body, &iocResp); err != nil {
		return nil, fmt.Errorf("iocpull: parse response: %w", err)
	}

	// Store in cache
	now := p.nowFunc()
	p.cache.Store(iocResp.IOCs, now)

	// Track If-Modified-Since for next request
	if iocResp.UpdatedAt != "" {
		p.lastUpdated = iocResp.UpdatedAt
	} else {
		p.lastUpdated = now.UTC().Format(http.TimeFormat)
	}

	return &PullResult{
		IOCs:      iocResp.IOCs,
		FromCache: false,
		UpdatedAt: p.lastUpdated,
	}, nil
}

// GetIOC looks up an IOC by fingerprint in the local cache.
func (p *IOCPuller) GetIOC(fingerprint string) (IOCEntry, bool) {
	return p.cache.Get(fingerprint)
}

// GetAllIOCs returns all IOCs currently in the local cache.
func (p *IOCPuller) GetAllIOCs() []IOCEntry {
	return p.cache.All()
}

// CheckFingerprint checks whether a fingerprint is present in the IOC cache.
// Returns the matching entry or nil if not found.
func (p *IOCPuller) CheckFingerprint(fingerprint string) *IOCEntry {
	entry, ok := p.cache.Get(fingerprint)
	if !ok {
		return nil
	}
	return &entry
}

// CacheSize returns the number of IOCs currently cached.
func (p *IOCPuller) CacheSize() int {
	return p.cache.Size()
}

// LastUpdated returns the timestamp of the last successful pull.
func (p *IOCPuller) LastUpdated() time.Time {
	return p.cache.UpdatedAt()
}

// Healthz checks Platform connectivity by issuing a GET to /healthz.
func (p *IOCPuller) Healthz() error {
	if !p.enabled {
		return fmt.Errorf("iocpull: disabled (no platform_url configured)")
	}

	endpoint := p.url + "/healthz"

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("iocpull: healthz request: %w", err)
	}
	req.Header.Set("User-Agent", "aegisgate-rampart/"+p.version)
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("iocpull: healthz: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("iocpull: healthz returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// StartPullLoop runs a background goroutine that pulls IOCs at the given
// interval. It stops when ctx is cancelled.
func (p *IOCPuller) StartPullLoop(ctx context.Context, interval time.Duration) {
	go func() {
		if !p.enabled {
			log.Printf("rampart: IOC pull loop disabled — exiting")
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Initial pull on startup
		if _, err := p.Pull(); err != nil {
			log.Printf("rampart: IOC pull error: %v", err)
		} else {
			log.Printf("rampart: IOC pull OK (%d entries)", p.CacheSize())
		}

		for {
			select {
			case <-ctx.Done():
				log.Printf("rampart: IOC pull loop stopped")
				return
			case <-ticker.C:
				result, err := p.Pull()
				if err != nil {
					log.Printf("rampart: IOC pull error: %v", err)
					continue
				}
				if result.FromCache {
					log.Printf("rampart: IOC pull not modified (cache: %d entries)", p.CacheSize())
				} else {
					log.Printf("rampart: IOC pull OK (%d entries)", len(result.IOCs))
				}
			}
		}
	}()
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// maskURL masks the URL for safe logging, showing only scheme and host.
func maskURL(rawURL string) string {
	// Simple mask — strip path and query
	if i := strings.Index(rawURL, "://"); i >= 0 {
		rest := rawURL[i+3:]
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			rest = rest[:j]
		}
		return rawURL[:i+3] + rest + "/..."
	}
	return "[invalid-url]"
}
