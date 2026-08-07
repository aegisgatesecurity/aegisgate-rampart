// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Platform Forwarder
// =========================================================================
//
// Forwards detection metadata to AegisGate Platform for SIEM integration,
// attestation, and audit trail. Only metadata is sent — never prompt text,
// PII values, or credentials.
//
// Privacy (12 non-negotiables):
//   - No prompt text is sent — only detection metadata
//   - No PII values sent — only categories and rule names
//   - No credentials sent
//   - Platform forwarding is opt-in (requires platform_url in config)
//   - Air-gap compatible — if platform_url is empty, forwarding is disabled
//
// =========================================================================

package platformforward

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/auditlog"
)

// Forwarder pushes detection events to AegisGate Platform.
type Forwarder struct {
	url     string
	client  *http.Client
	enabled bool

	// For testing
	nowFunc func() time.Time
}

// PlatformEvent is the metadata-only payload sent to Platform.
// No prompt text, no PII values, no credentials — only detection metadata.
type PlatformEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	Source        string    `json:"source"`    // "rampart"
	Version       string    `json:"version"`   // rampart version
	Direction     string    `json:"direction"` // "request" or "response"
	Host          string    `json:"host"`      // e.g. "api.openai.com"
	Path          string    `json:"path,omitempty"`
	TotalDets     int       `json:"total_detections"`
	Blocked       bool      `json:"blocked"`
	PIICategories []string  `json:"pii_categories,omitempty"`
	SecretTypes   []string  `json:"secret_types,omitempty"`
	MLScore       float64   `json:"ml_score,omitempty"`
	Categories    []string  `json:"categories,omitempty"`
	Severities    []string  `json:"severities,omitempty"`
	Rules         []string  `json:"rules,omitempty"`
}

// New creates a Platform forwarder. If url is empty, forwarding is disabled.
func New(url string) *Forwarder {
	enabled := url != ""
	if enabled {
		log.Printf("rampart: platform forwarding enabled → %s", url)
	} else {
		log.Printf("rampart: platform forwarding disabled (no platform_url configured)")
	}

	return &Forwarder{
		url:     url,
		client:  &http.Client{Timeout: 5 * time.Second},
		enabled: enabled,
		nowFunc: time.Now,
	}
}

// Forward sends a detection event to Platform. Non-blocking on error.
func (f *Forwarder) Forward(entry auditlog.Entry) {
	if !f.enabled {
		return
	}

	event := PlatformEvent{
		Timestamp:     entry.Timestamp,
		Source:        "rampart",
		Version:       "0.2.0",
		Direction:     entry.Direction,
		Host:          entry.Host,
		Path:          entry.Path,
		TotalDets:     entry.TotalDets,
		Blocked:       entry.Blocked,
		PIICategories: entry.PIICategories,
		SecretTypes:   entry.SecretTypes,
		MLScore:       entry.MLScore,
		Categories:    entry.Categories,
		Severities:    entry.Severities,
		Rules:         entry.Rules,
	}

	go f.send(event)
}

// send posts the event to Platform. Logs errors but never blocks the caller.
func (f *Forwarder) send(event PlatformEvent) {
	payload, err := json.Marshal(event)
	if err != nil {
		log.Printf("rampart: platform forward marshal error: %v", err)
		return
	}

	resp, err := f.client.Post(f.url, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("rampart: platform forward error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("rampart: platform forward rejected: HTTP %d", resp.StatusCode)
	}
}

// Enabled returns whether forwarding is active.
func (f *Forwarder) Enabled() bool {
	return f.enabled
}

// String implements fmt.Stringer for diagnostics.
func (f *Forwarder) String() string {
	if !f.enabled {
		return "platform forwarding disabled"
	}
	return fmt.Sprintf("platform forwarding → %s", f.url)
}
