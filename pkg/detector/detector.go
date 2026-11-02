package detector

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/detectors"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/ml"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/response"
)

// Detector runs the local detection engine (regex + ML).
// It reuses the same detection logic as Platform v4.0.0.
type Detector struct {
	guard   *response.ResponseGuard
	ml      *ml.ThreatDetector
	mlReady bool
}

// Config holds detector configuration.
type Config struct {
	// EnableML enables the ONNX ML model for threat detection.
	EnableML bool

	// ModelPath is the path to the ONNX model file.
	ModelPath string

	// MLThreshold is the score threshold for ML threat detection.
	MLThreshold float64

	// ShadowMode runs ML in shadow mode (logs but doesn't block).
	ShadowMode bool

	// EnablePII enables PII detection.
	EnablePII bool

	// EnableSecrets enables secret/API key detection.
	EnableSecrets bool

	// EnableXSS enables XSS vector detection.
	EnableXSS bool

	// EnableCompliance enables compliance framework detection.
	EnableCompliance bool

	// StrictMode fails-closed on any detection.
	StrictMode bool
}

// DefaultConfig returns production defaults.
func DefaultConfig() *Config {
	return &Config{
		EnablePII:        true,
		EnableSecrets:    true,
		EnableXSS:        true,
		EnableCompliance: true,
		EnableML:         true,
		ModelPath:        "/opt/aegisgate-rampart/models/threat_cnn_bilstm.onnx",
		MLThreshold:      0.5, // v13 calibrated threshold (matches Platform proxy default)
		ShadowMode:       true,
		StrictMode:       false,
	}
}

// New creates a new Detector with the response guard and optional ML model.
func New(cfg *Config) (*Detector, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	guardCfg := &response.ResponseGuardConfig{
		EnablePIIScanner:          cfg.EnablePII,
		EnableSecretDetection:     cfg.EnableSecrets,
		EnableXSSDetection:        cfg.EnableXSS,
		EnableComplianceDetection: cfg.EnableCompliance,
		EnableToxicityFilter:      true,
		EnableHallucination:       false,
		StrictMode:                cfg.StrictMode,
	}

	d := &Detector{
		guard: response.NewResponseGuardWithConfig(guardCfg),
	}

	// Initialize ML threat detector
	if cfg.EnableML {
		mlCfg := ml.DetectorConfig{
			Enabled:           !cfg.ShadowMode,
			ShadowMode:        cfg.ShadowMode,
			Threshold:         cfg.MLThreshold,
			ModelPath:         cfg.ModelPath,
			MaxSequenceLength: 256,
			Timeout:           10,
		}

		mlDetector := ml.NewThreatDetector(mlCfg)
		if err := mlDetector.LoadModel(cfg.ModelPath); err != nil {
			// ML model load failure is non-fatal — heuristic fallback is used
			fmt.Fprintf(os.Stderr, "rampart: ML model load failed (%v), using heuristic fallback\n", err)
		} else {
			d.ml = mlDetector
			d.mlReady = true
		}
	}

	return d, nil
}

// Result represents a detection event.
type Result struct {
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Text        string  `json:"text,omitempty"`
	Rule        string  `json:"rule"`
	IsThreat    bool    `json:"is_threat"`
	Blocked     bool    `json:"blocked"`
	BlockReason string  `json:"block_reason,omitempty"`
	MLScore     float64 `json:"ml_score,omitempty"`
}

// Summary holds aggregated detection results.
type Summary struct {
	TotalDetections int             `json:"total_detections"`
	Blocked         bool            `json:"blocked"`
	BlockReason     string          `json:"block_reason,omitempty"`
	Results         []Result        `json:"results"`
	PIICategories   []string        `json:"pii_categories,omitempty"`
	SecretTypes     []string        `json:"secret_types,omitempty"`
	Compliance      map[string]bool `json:"compliance,omitempty"`
	MLScore         float64         `json:"ml_score,omitempty"`
	LatencyMs       int64           `json:"latency_ms"`
}

// Detect scans input text for PII, secrets, prompt injection, XSS, and compliance violations.
// Returns a Summary of all findings.
func (d *Detector) Detect(text string) (*Summary, error) {
	return d.DetectWithContext(context.Background(), text)
}

// DetectWithContext scans input text with context.
func (d *Detector) DetectWithContext(ctx context.Context, text string) (*Summary, error) {
	if text == "" {
		return &Summary{}, nil
	}

	// 1. Run response guard (regex-based detection: PII, secrets, XSS, compliance)
	scanResult, err := d.guard.Scan(ctx, text)
	if err != nil {
		return nil, fmt.Errorf("response guard scan: %w", err)
	}

	summary := &Summary{
		Blocked:     !scanResult.Allowed,
		BlockReason: scanResult.BlockReason,
		Results:     make([]Result, 0, len(scanResult.Threats)),
		Compliance:  make(map[string]bool),
		LatencyMs:   scanResult.LatencyMs,
	}

	// Convert threats to results
	for _, t := range scanResult.Threats {
		r := Result{
			Category:   t.Type,
			Severity:   severityIntToString(t.Severity),
			Confidence: 1.0,
			Text:       t.Message,
			Rule:       t.Pattern,
			IsThreat:   true,
		}
		summary.Results = append(summary.Results, r)
	}
	summary.TotalDetections = len(summary.Results)

	// Collect PII categories
	for _, cat := range scanResult.DetectedPII {
		summary.PIICategories = append(summary.PIICategories, string(cat))
	}

	// Collect secret types
	summary.SecretTypes = scanResult.DetectedSecrets

	// Compliance results
	for framework, result := range scanResult.ComplianceReports {
		summary.Compliance[framework] = result.Compliant
	}

	// Truncate to 64KB (mirrors ResponseGuard's maxScanBytes) to prevent
	// O(n*k) regex cost on very large inputs. The guard already scanned the
	// first 64KB; DetectAll and NormalizeAllVariants run against the same
	// patterns so truncating here avoids redundant work on the tail.
	const detectorMaxScanBytes = 64 * 1024

	// 2. Run ML threat detection (supplementary layer)
	// Feed only the original text to the ML model, not normalization variants.
	// The variants (ROT13, keyboard-walk, l33t, etc.) are designed for regex
	// pattern matching, not neural network inference. The CharCNN-BiLSTM was
	// trained on raw text and produces false positives on ROT13-transformed
	// benign text (e.g., "Hello" → "Uryyb" scores 0.99+). The model's own
	// character-level normalization handles evasion patterns that the variant
	// pipeline covers for regex. This matches Platform's request path approach.
	// (ref: upstream/aegisgate/pkg/proxy/proxy.go:710-720)
	if d.ml != nil {
		scanContent := text
		if len(scanContent) > detectorMaxScanBytes {
			scanContent = scanContent[:detectorMaxScanBytes]
		}
		mlResult := d.ml.Detect(scanContent)
		summary.MLScore = mlResult.Score
		if mlResult.IsThreat {
			summary.Results = append(summary.Results, Result{
				Category:   "ml_threat",
				Severity:   "high",
				Confidence: mlResult.Score,
				Text:       "Neural network detected adversarial prompt pattern",
				Rule:       "char_cnn_bilstm",
				IsThreat:   true,
				MLScore:    mlResult.Score,
			})
			summary.TotalDetections++
		}
	}

	// 3. Run all-detector scan on normalization variants (evasion-resistant).
	// Platform calls scanner.NormalizeAllVariants() then ScanFast() on each
	// variant with early-exit on block. We mirror that here: scan the original
	// first, then each deobfuscated variant, collecting new matches.
	//
	// NormalizeAllVariants returns the original text as variants[0], so the
	// first iteration covers the same content as the old single-pass scan.
	variants := detectors.NormalizeAllVariants(text)
	seenMatches := make(map[string]bool) // deduplicate by Category:Value
	for _, v := range variants {
		if v == "" {
			continue
		}
		scanText := v
		if len(scanText) > detectorMaxScanBytes {
			scanText = scanText[:detectorMaxScanBytes]
		}
		allMatches := detectors.DetectAll(scanText)
		for _, m := range allMatches {
			key := string(m.Category) + ":" + m.Value
			if seenMatches[key] {
				continue
			}
			seenMatches[key] = true
			r := Result{
				Category:   string(m.Category),
				Severity:   string(m.Severity),
				Confidence: m.Confidence,
				Text:       m.Value,
				Rule:       m.Category,
			}
			summary.Results = append(summary.Results, r)
		}
	}

	// Update total detections count to include all-detector results
	summary.TotalDetections = len(summary.Results)

	// 4. Educational context filtering — suppress FPs on educational/security
	// training questions that mention attack terms in a learning context.
	// e.g., "What is LOLBins and why do attackers use it?" should not be
	// blocked just because it mentions "LOLBins".
	if isEducationalContext(text) {
		filtered := summary.Results[:0]
		for _, r := range summary.Results {
			if !isEducationalFP(r.Category, r.Text) {
				filtered = append(filtered, r)
			}
		}
		summary.Results = filtered
		summary.TotalDetections = len(summary.Results)
		if summary.TotalDetections == 0 {
			summary.Blocked = false
			summary.BlockReason = ""
		}
	}

	return summary, nil
}

// DetectBatch scans multiple texts and returns results for each.
func (d *Detector) DetectBatch(texts []string) ([]*Summary, error) {
	results := make([]*Summary, len(texts))
	for i, text := range texts {
		result, err := d.Detect(text)
		if err != nil {
			return nil, fmt.Errorf("detect batch item %d: %w", i, err)
		}
		results[i] = result
	}
	return results, nil
}

// severityIntToString converts Platform's int severity to string.
func severityIntToString(severity int) string {
	switch {
	case severity >= 5:
		return "critical"
	case severity >= 4:
		return "high"
	case severity >= 3:
		return "medium"
	default:
		return "low"
	}
}

// isEducationalContext checks if the text starts with an educational question
// pattern (e.g., "What is LOLBins?", "Explain the kill chain model").
func isEducationalContext(text string) bool {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) > 60 {
		trimmed = trimmed[:60]
	}
	lower := strings.ToLower(trimmed)

	eduPatterns := []string{
		"how do i ", "how to ", "how does ", "how should ", "how can i ",
		"what is ", "what's ", "what are ", "what's the ", "what does ",
		"explain ", "describe ",
		"difference between ",
		"best practices for ", "best practice for ",
		"why is ", "why are ", "why do ",
		"when should ", "when is ",
	}

	for _, p := range eduPatterns {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}

	return false
}

// isEducationalFP checks if a detection result is a likely false positive
// in an educational context. These are categories where mentioning the term
// in a question ("What is LOLBins?") should not be treated as an attack.
func isEducationalFP(category, matchedText string) bool {
	// Categories commonly discussed in security education where the term
	// itself triggers the pattern (e.g., "What is LOLBins?" matches evasion_lolbin)
	eduFPCategories := map[string]bool{
		"evasion":           true,
		"path-traversal":    true,
		"pii-financial":     true,
		"pii-us-core":       true,
		"pii-us-extended":   true,
		"pii-international": true,
	}

	if eduFPCategories[category] {
		return true
	}

	// Check by pattern name (the Category field in Match is the pattern name)
	if strings.Contains(category, "evasion") {
		return true
	}
	if strings.Contains(category, "sensitive_file") {
		return true
	}
	// ICD-10 codes in educational context
	if strings.Contains(matchedText, "ICD-10") || strings.Contains(category, "icd") {
		return true
	}

	return false
}
