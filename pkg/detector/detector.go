package detector

import (
	"context"
	"fmt"
	"os"

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
		MLThreshold:      0.7,
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
			MaxSequenceLength: 128,
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

	// 2. Run ML threat detection (supplementary layer)
	if d.ml != nil {
		mlResult := d.ml.Detect(text)
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

	// 3. Run all-detector scan (comprehensive regex from detectors package)
	allMatches := detectors.DetectAll(text)
	for _, m := range allMatches {
		// Avoid duplicating results already captured by response guard
		r := Result{
			Category:   string(m.Category),
			Severity:   string(m.Severity),
			Confidence: m.Confidence,
			Text:       m.Value,
			Rule:       m.Category,
		}
		summary.Results = append(summary.Results, r)
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
