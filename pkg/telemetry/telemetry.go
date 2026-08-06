package telemetry

import (
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

// Telemetry sends anonymized detection events to an optional Platform backend.
// When PlatformURL is empty, all telemetry is disabled (air-gap mode).
type Telemetry struct {
	cfg *config.Config
}

// New creates a new Telemetry client.
// Returns a no-op client when PlatformURL is empty.
func New(cfg *config.Config) *Telemetry {
	return &Telemetry{cfg: cfg}
}

// Send sends a detection event to Platform.
// No-op when PlatformURL is empty (privacy by default).
func (t *Telemetry) Send(event map[string]interface{}) error {
	if t.cfg.PlatformURL == "" {
		return nil // air-gap mode
	}
	// Phase 1: Wire to Platform telemetry API
	return nil
}
