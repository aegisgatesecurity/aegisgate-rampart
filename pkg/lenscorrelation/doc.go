// SPDX-License-Identifier: Apache-2.0
// Package lenscorrelation implements the Lens → Rampart signal correlation
// channel. When both Lens (browser extension) and Rampart (MITM proxy) are
// running on the same machine, Lens can send real-time detection signals
// to Rampart for cross-layer correlation.
//
// This enables "defense in depth" correlation: if Lens detects a prompt
// injection in the browser AND Rampart detects a PII leak in the proxy
// layer for the same domain, the combined signal can trigger a block even
// if neither detection alone would have blocked.
//
// Architecture:
//   - Lens sends detection signals via POST /api/v1/lens-signals to Rampart
//   - Rampart's signal receiver stores signals in a sliding window
//   - The correlator checks for cross-layer detections on the same domain
//   - Correlated signals can escalate severity or trigger blocks
//
// Air-gap: This is localhost-only communication. No external network
// access required. Lens checks if Rampart is running before sending.
//
// Privacy: Signals contain only metadata (hashed domain, category,
// severity, rule ID). No prompt text, no PII values, no page content.
package lenscorrelation
