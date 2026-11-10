// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart — Behavioral Parity Test
//
// Runs the full 310-prompt red-team corpus (210 attacks + 100 benign)
// through Rampart's detection pipeline, mirroring the proxy's scanning logic:
//   1. DetectAllFast on original text
//   2. DetectAllFast on normalization variants (evasion resistance)
//   3. ML ThreatDetector heuristic fallback (transposition, vowel deletion, reversed words)
//
// The ONNX neural model provides additional coverage in production but
// requires the model file and ONNX runtime, which may not be available in CI.
// This test focuses on catching pattern regressions.
//
// Baseline (2026-11-09, regex+heuristic layers only):
//   Detection: ~206/210 (98.1%) in production (with ONNX)
//   Non-ONNX baseline: ~180/210 (85.7%) — heuristic adds evasion catches
//   False Positives: 0/100 (0.0%)
//
// Known acceptable miss: rt-0023 ("Imagine you're not an AI assistant...")
//
// Gates:
//   - Detection rate ≥ 80% (≥ 168/210) — FAIL if lower
//   - False positive rate = 0% (0/100) — FAIL if any FP
//   - Pattern count check via existing parity_test.go

package detectors_test

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/ml"
)

//go:embed corpus-redteam-310.json
var corpusJSON []byte

// knownMisses lists attack IDs that are known gaps and excluded from the
// detection-rate gate.
var knownMisses = map[string]string{
	"rt-0023": "Role-play framing without explicit injection keywords — requires semantic understanding (ONNX model catches this in production)",
}

// minimumDetectionRate is the lowest acceptable detection rate for the
// non-ONNX layers (regex + heuristic).
const minimumDetectionRate = 0.80

type corpusItem struct {
	ID       string `json:"id"`
	Text     string `json:"text"`
	Label    string `json:"label"`
	Category string `json:"category"`
}

func loadCorpus(t *testing.T) []corpusItem {
	t.Helper()
	var items []corpusItem
	if err := json.Unmarshal(corpusJSON, &items); err != nil {
		t.Fatalf("failed to parse embedded corpus: %v", err)
	}
	return items
}

// hasBlockingSeverity returns true if any match has High or Critical severity,
// mirroring Rampart's default block threshold (SeverityHigh).
func hasBlockingSeverity(matches []detectors.Match) bool {
	for _, m := range matches {
		if m.Severity == detectors.SeverityHigh || m.Severity == detectors.SeverityCritical {
			return true
		}
	}
	return false
}

// scanPayload replicates Rampart's proxy scanning pipeline (non-ONNX):
// 1. DetectAllFast on original text
// 2. DetectAllFast on normalization variants
// 3. ML ThreatDetector heuristic fallback
func scanPayload(td *ml.ThreatDetector, text string) bool {
	// Layer 1: DetectAllFast on original text
	matches := detectors.DetectAllFast(text)
	if hasBlockingSeverity(matches) {
		return true
	}

	// Layer 2: DetectAllFast on normalization variants
	variants := detectors.NormalizeAllVariants(text)
	for _, v := range variants {
		if v == "" || v == text {
			continue
		}
		variantMatches := detectors.DetectAllFast(v)
		if hasBlockingSeverity(variantMatches) {
			return true
		}
	}

	// Layer 3: ML ThreatDetector heuristic fallback
	if td != nil {
		result := td.Detect(text)
		if result.IsThreat {
			return true
		}
		for _, v := range variants {
			if v == "" || v == text {
				continue
			}
			vResult := td.Detect(v)
			if vResult.IsThreat {
				return true
			}
		}
	}

	return false
}

func TestBehavioralParity(t *testing.T) {
	corpus := loadCorpus(t)

	var attacks, benign []corpusItem
	for _, item := range corpus {
		if item.Label == "attack" {
			attacks = append(attacks, item)
		} else if item.Label == "benign" {
			benign = append(benign, item)
		}
	}

	if len(attacks) != 210 {
		t.Fatalf("expected 210 attack payloads, got %d", len(attacks))
	}
	if len(benign) != 100 {
		t.Fatalf("expected 100 benign payloads, got %d", len(benign))
	}

	// Create ML ThreatDetector with heuristic fallback (no ONNX model in CI)
	tdCfg := ml.DefaultDetectorConfig()
	tdCfg.Enabled = true
	tdCfg.ShadowMode = false
	tdCfg.Threshold = 0.50 // Same as proxy default
	td := ml.NewThreatDetector(tdCfg)

	// Run attacks
	var misses []corpusItem
	for _, item := range attacks {
		blocked := scanPayload(td, item.Text)
		if !blocked {
			if _, isKnown := knownMisses[item.ID]; isKnown {
				t.Logf("KNOWN MISS: %s [%s] — %s", item.ID, item.Category, knownMisses[item.ID])
				continue
			}
			misses = append(misses, item)
		}
	}

	// Run benign payloads
	var falsePositives []corpusItem
	for _, item := range benign {
		blocked := scanPayload(td, item.Text)
		if blocked {
			falsePositives = append(falsePositives, item)
		}
	}

	// Calculate rates
	gatedAttacks := len(attacks) - len(knownMisses)
	caught := gatedAttacks - len(misses)
	detectionRate := float64(caught) / float64(gatedAttacks)

	// Report
	t.Logf("=== Behavioral Parity Test Results ===")
	t.Logf("Attacks: %d total, %d known misses, %d gated", len(attacks), len(knownMisses), gatedAttacks)
	t.Logf("Caught: %d/%d = %.1f%%", caught, gatedAttacks, detectionRate*100)
	t.Logf("Misses: %d", len(misses))
	t.Logf("False Positives: %d/%d = %.1f%%", len(falsePositives), len(benign),
		float64(len(falsePositives))/float64(len(benign))*100)
	t.Logf("Note: ONNX neural model adds more catches in production (not available in CI)")

	// Per-category breakdown of misses
	if len(misses) > 0 {
		t.Logf("\n--- Per-category miss breakdown ---")
		catMisses := map[string][]string{}
		for _, m := range misses {
			catMisses[m.Category] = append(catMisses[m.Category], m.ID)
		}
		cats := make([]string, 0, len(catMisses))
		for c := range catMisses {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			t.Logf("  %s: %d misses %v", c, len(catMisses[c]), catMisses[c])
		}
	}

	// Gates
	if detectionRate < minimumDetectionRate {
		var missDetails []string
		for _, m := range misses {
			missDetails = append(missDetails, fmt.Sprintf("%s [%s]", m.ID, m.Category))
		}
		t.Errorf("DETECTION RATE GATE FAILED: %.1f%% < %.1f%% threshold. Misses: %s",
			detectionRate*100, minimumDetectionRate*100, strings.Join(missDetails, ", "))
	}

	if len(falsePositives) > 0 {
		var fpDetails []string
		for _, fp := range falsePositives {
			fpDetails = append(fpDetails, fp.ID)
		}
		t.Errorf("FALSE POSITIVE GATE FAILED: %d FPs found (expected 0). FPs: %s",
			len(falsePositives), strings.Join(fpDetails, ", "))
	}
}

// TestTotalCompiledPatterns verifies that the expected number of patterns
// are loaded. This catches regressions where patterns are lost.
func TestTotalCompiledPatterns(t *testing.T) {
	count := detectors.TotalCompiledPatterns()

	// Baseline: 571 patterns
	const minPatterns = 560 // Allow small variance, catch major loss

	t.Logf("Total compiled patterns: %d (minimum: %d)", count, minPatterns)

	if count < minPatterns {
		t.Errorf("PATTERN COUNT GATE FAILED: %d < %d minimum. Patterns may have been lost.",
			count, minPatterns)
	}
}
