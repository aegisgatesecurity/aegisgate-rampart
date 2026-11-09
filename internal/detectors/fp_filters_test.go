// SPDX-License-Identifier: Apache-2.0
// Test coverage for false-positive filter functions in fp_filters.go
// and normalization functions in normalize.go

package detectors

import (
	"strings"
	"testing"
)

// ============================================================================
// fp_filters.go tests
// ============================================================================

func TestIsBenignTwilioKey(t *testing.T) {
	tests := []struct {
		name   string
		match  string
		expect bool
	}{
		{"real hex key with digits", "SK1234567890abcdef1234567890aXXXX", false},
		{"real key many digits", "SK9876543210987654321XX", false},
		{"english word concat no digits", "accessrepositoryofresearchpapers", true},
		{"english words minimal digits", "skabcdef", true}, // only 0 digits
		{"exactly 2 digits", "sk12abcdef", true},           // digits < 3
		{"exactly 3 digits", "sk123abcdef", false},         // digits >= 3
		{"empty string", "", true},                         // 0 digits < 3
		{"all digits", "1234567890", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBenignTwilioKey(tt.match)
			if got != tt.expect {
				t.Errorf("isBenignTwilioKey(%q) = %v, want %v", tt.match, got, tt.expect)
			}
		})
	}
}

func TestIsBenignSexualContent(t *testing.T) {
	// isBenignSexualContent looks at content[matchStart-80 : matchStart] for benign indicators.
	// The benign context must appear BEFORE the matched word.
	tests := []struct {
		name       string
		content    string
		matchStart int
		expect     bool
	}{
		{
			"Royal Commission context",
			"The Royal Commission into institutional sexual abuse responses",
			32, // "sexual" starts at position 32
			true,
		},
		{
			"AI safety refusal context",
			"I am trained to not generate sexual content and I refuse such requests",
			27, // "sexual" starts at position 27
			true,
		},
		{
			"policy discussion",
			"Our safety guidelines prohibit sexual content and our filter blocks it",
			27, // "sexual" starts at position 27
			true,
		},
		{
			"awareness discussion",
			"We are preventing sexual exploitation through awareness programs",
			18, // "sexual" starts at position 18
			true,
		},
		{
			"no benign context",
			"This is some random text about cooking recipes and food",
			30,
			false,
		},
		{
			"empty content",
			"",
			0,
			false,
		},
		{
			"short content no context",
			"hello",
			0,
			false,
		},
		{
			"moderation discussion",
			"The moderation system blocks sexual content per our guidelines",
			27, // "sexual" starts at position 27
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBenignSexualContent(tt.content, tt.matchStart)
			if got != tt.expect {
				t.Errorf("isBenignSexualContent = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestIsBenignExfilTransfer(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		content    string
		matchStart int
		expect     bool
	}{
		{
			"S3 upload with lambda context",
			"upload file to s3",
			strings.Repeat("x", 50) + " We use a lambda trigger to upload file to s3 for the pipeline " + strings.Repeat("y", 50),
			50,
			true,
		},
		{
			"S3 upload with architecture context",
			"upload file to s3",
			strings.Repeat("x", 50) + " The architecture includes upload file to s3 as a backup workflow " + strings.Repeat("y", 50),
			50,
			true,
		},
		{
			"S3 upload with thumbnail context",
			"upload file to s3",
			strings.Repeat("x", 50) + " We resize and upload file to s3 to create a thumbnail in the bucket " + strings.Repeat("y", 50),
			50,
			true,
		},
		{
			"S3 upload no benign context",
			"upload file to s3",
			strings.Repeat("x", 50) + " Just upload file to s3 and exfiltrate all the data " + strings.Repeat("y", 50),
			50,
			false,
		},
		{
			"not S3 upload pattern",
			"transfer data to external server",
			strings.Repeat("x", 50) + " transfer data to external server " + strings.Repeat("y", 50),
			50,
			false,
		},
		{
			"empty match",
			"",
			"some content",
			0,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBenignExfilTransfer(tt.match, tt.content, tt.matchStart)
			if got != tt.expect {
				t.Errorf("isBenignExfilTransfer = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestIsBenignMatch(t *testing.T) {
	tests := []struct {
		name        string
		patternName string
		match       string
		content     string
		matchStart  int
		matchEnd    int
		expect      bool
	}{
		{"twilio key benign", "secret_twilio_key", "accessrepositoryofresearchpapers", "", 0, 30, true},
		{"twilio key real", "secret_twilio_key", "SK1234567890abcdef1234567890aXXXX", "", 0, 34, false},
		{"sexual content benign", "toxicity_sexual", "sexual",
			"Our safety guidelines prohibit sexual content per our policy",
			27, 33, true},
		{"sql comment benign", "sqli_comment_evasion", "# create a button widget", "", 0, 24, true},
		{"sql comment not benign", "sqli_comment_evasion", "# DROP TABLE users", "", 0, 18, false},
		{"exfil transfer benign", "exfil_external_transfer", "upload file to s3",
			strings.Repeat("x", 50) + " lambda trigger upload file to s3 pipeline " + strings.Repeat("y", 50),
			50, 66, true},
		{"pii placeholder benign", "pii_id_generic_alphanumeric", "PASSPORTNUMPLACEHOLDER_14", "", 0, 24, true},
		{"pii placeholder not benign", "pii_id_generic_alphanumeric", "ABC123456789", "", 0, 12, false},
		{"code credential benign", "secret_labeled_credential", "password = $_POST[\"password\"]", "", 0, 30, true},
		{"code credential not benign", "secret_labeled_credential", "password = hunter2", "", 0, 17, false},
		{"unknown pattern", "unknown_pattern", "some text", "", 0, 9, false},
		{"empty pattern name", "", "some text", "", 0, 9, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBenignMatch(tt.patternName, tt.match, tt.content, tt.matchStart, tt.matchEnd)
			if got != tt.expect {
				t.Errorf("isBenignMatch(%q) = %v, want %v", tt.patternName, got, tt.expect)
			}
		})
	}
}

// ============================================================================
// normalize.go tests
// ============================================================================

func TestNormalizeForComparison(t *testing.T) {
	// Basic text normalization
	result := NormalizeForComparison("Hello World")
	if result == "" {
		t.Error("NormalizeForComparison returned empty for non-empty input")
	}
	if !strings.Contains(strings.ToLower(result), "hello") {
		t.Errorf("NormalizeForComparison should contain normalized text, got %q", result)
	}

	// ROT13 encoded text
	rot13Input := "vtaber" // ROT13 of "ignore"
	result = NormalizeForComparison(rot13Input)
	if !strings.Contains(result, "ignore") {
		t.Errorf("NormalizeForComparison should decode ROT13, got %q", result)
	}

	// Keyboard walk
	kwInput := "1qaz2wsx"
	result = NormalizeForComparison(kwInput)
	// Should produce some variant
	if result == "" {
		t.Error("NormalizeForComparison returned empty for keyboard walk input")
	}

	// Empty input
	result = NormalizeForComparison("")
	if result != "" {
		t.Errorf("NormalizeForComparison empty should return empty, got %q", result)
	}
}

func TestNormalizeDespaced(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"short input", "ab", "ab"},
		{"no spacing", "helloworld", "helloworld"},
		{"normal spacing", "hello world foo", "hello world foo"},
		{"despaced evasion", "i g n o r e   a l l   p r e v i o u s", "ignore all previous"},
		{"mixed word boundaries", "a b c  hello  d e f", "abc hello def"},
		{"tabs as separators", "i\tg\tn\to\tr\te", "ignore"},
		{"too few alphanum", "a b c", "a b c"}, // totalAlphaNum < 4
		{"low ratio spacing", "abcdef ghijkl mnopqr", "abcdef ghijkl mnopqr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeDespaced(tt.input)
			if got != tt.expect {
				t.Errorf("NormalizeDespaced(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}
