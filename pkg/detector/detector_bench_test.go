package detector

import (
	"strings"
	"testing"
)

// BenchmarkDetect benchmarks the detection engine with realistic AI traffic.
func BenchmarkDetect(b *testing.B) {
	cfg := &Config{
		EnablePII:        true,
		EnableSecrets:    true,
		EnableXSS:        true,
		EnableCompliance: true,
		EnableML:         false, // No ONNX model in CI; regex-only path
		ShadowMode:       true,
		StrictMode:       false,
	}

	det, err := New(cfg)
	if err != nil {
		b.Fatalf("New detector: %v", err)
	}

	// Realistic AI prompt text with embedded PII (email) and a secret (AWS key).
	input := `Please summarize the following email from alice@example.com. Also check if my AWS key AKIAIOSFODNN7EXAMPLE is still valid. The response should include a <script>alert('xss')</script> check as well.`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := det.Detect(input)
		if err != nil {
			b.Fatalf("Detect failed: %v", err)
		}
	}
}

// BenchmarkDetectClean benchmarks detection on clean (non-malicious) text.
func BenchmarkDetectClean(b *testing.B) {
	cfg := &Config{
		EnablePII:        true,
		EnableSecrets:    true,
		EnableXSS:        true,
		EnableCompliance: true,
		EnableML:         false,
		ShadowMode:       true,
		StrictMode:       false,
	}

	det, err := New(cfg)
	if err != nil {
		b.Fatalf("New detector: %v", err)
	}

	input := `The weather today is sunny with a high of 72 degrees. I went to the park and read a book about machine learning fundamentals.`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := det.Detect(input)
		if err != nil {
			b.Fatalf("Detect failed: %v", err)
		}
	}
}

// BenchmarkDetectLargeInput benchmarks detection on a large text payload.
func BenchmarkDetectLargeInput(b *testing.B) {
	cfg := &Config{
		EnablePII:        true,
		EnableSecrets:    true,
		EnableXSS:        true,
		EnableCompliance: true,
		EnableML:         false,
		ShadowMode:       true,
		StrictMode:       false,
	}

	det, err := New(cfg)
	if err != nil {
		b.Fatalf("New detector: %v", err)
	}

	// Build a ~50KB input: 1000 lines of typical chat + scattered PII.
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("This is a line of typical AI chat conversation about software engineering.\n")
	}
	sb.WriteString("Contact me at bob@company.com for details.\n")
	sb.WriteString("My GitHub token is ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.\n")
	sb.WriteString("<img src=x onerror=prompt('xss')>\n")

	input := sb.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := det.Detect(input)
		if err != nil {
			b.Fatalf("Detect failed: %v", err)
		}
	}
}

// BenchmarkDetectEmpty benchmarks detection on empty input (fast path).
func BenchmarkDetectEmpty(b *testing.B) {
	cfg := &Config{
		EnablePII:        true,
		EnableSecrets:    true,
		EnableXSS:        true,
		EnableCompliance: true,
		EnableML:         false,
		ShadowMode:       true,
		StrictMode:       false,
	}

	det, err := New(cfg)
	if err != nil {
		b.Fatalf("New detector: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := det.Detect("")
		if err != nil {
			b.Fatalf("Detect failed: %v", err)
		}
	}
}

// BenchmarkDetectPIIOnly benchmarks detection with only PII scanning enabled.
func BenchmarkDetectPIIOnly(b *testing.B) {
	cfg := &Config{
		EnablePII:        true,
		EnableSecrets:    false,
		EnableXSS:        false,
		EnableCompliance: false,
		EnableML:         false,
		ShadowMode:       true,
		StrictMode:       false,
	}

	det, err := New(cfg)
	if err != nil {
		b.Fatalf("New detector: %v", err)
	}

	input := `My SSN is 123-45-6789 and my email is user@example.com. Call me at (555) 123-4567.`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := det.Detect(input)
		if err != nil {
			b.Fatalf("Detect failed: %v", err)
		}
	}
}

// BenchmarkDetectBatch benchmarks batch detection on multiple inputs.
func BenchmarkDetectBatch(b *testing.B) {
	cfg := &Config{
		EnablePII:        true,
		EnableSecrets:    true,
		EnableXSS:        true,
		EnableCompliance: true,
		EnableML:         false,
		ShadowMode:       true,
		StrictMode:       false,
	}

	det, err := New(cfg)
	if err != nil {
		b.Fatalf("New detector: %v", err)
	}

	texts := []string{
		"My API key is sk-abc123def456ghi789jkl012mno345.",
		"The weather is nice today, no threats here.",
		"<script>document.cookie</script> XSS attack attempt.",
		"Please email john.doe@enterprise.org for the report.",
		"AWS secret key: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := det.DetectBatch(texts)
		if err != nil {
			b.Fatalf("DetectBatch failed: %v", err)
		}
	}
}
