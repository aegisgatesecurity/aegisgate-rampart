package detectors

import "strings"

// isBenignMatch performs post-match validation to filter false positives
// that regex patterns alone cannot distinguish from real threats.
// It checks the matched text and its surrounding context for indicators
// that the match is benign (educational, code examples, institutional discussion, etc.).
//
// This is called after isKnownTestKey and before creating a Match.
// Returns true if the match should be skipped (is benign).
func isBenignMatch(patternName, match, content string, matchStart, matchEnd int) bool {
	switch patternName {
	case "secret_twilio_key":
		return isBenignTwilioKey(match)
	case "toxicity_sexual":
		return isBenignSexualContent(content, matchStart)
	case "sqli_comment_evasion":
		return isBenignSqlComment(match)
	case "exfil_external_transfer":
		return isBenignExfilTransfer(match, content, matchStart)
	case "pii_id_generic_alphanumeric":
		return isBenignPiiPlaceholder(match)
	case "secret_labeled_credential":
		return isBenignCodeCredential(match, content, matchStart)
	default:
		return false
	}
}

// isBenignTwilioKey checks if a Twilio key match is actually a concatenation
// of English words created by space-removal normalization variants.
// Real Twilio keys are hex strings (0-9, a-f) with many digits.
// English word concatenations like "accessrepositoryofresearchpapers" have 0 digits.
func isBenignTwilioKey(match string) bool {
	digits := 0
	for _, c := range match {
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	return digits < 3
}

// isBenignSexualContent checks if a sexual content match occurs in a benign
// context: institutional discussion (Royal Commission), AI safety refusals,
// or policy/moderation discussions.
func isBenignSexualContent(content string, matchStart int) bool {
	start := matchStart - 80
	if start < 0 {
		start = 0
	}
	before := strings.ToLower(content[start:matchStart])

	benignIndicators := []string{
		"commission", "institutional", "victims of", "responses to",
		"reporting", "investigation", "preventing", "awareness",
		"trained to not", "cannot", "can not", "refuse", "decline",
		"not answer", "not generate", "policies", "guidelines",
		"safety", "moderation", "filter", "block", "prohibit",
		"child abuse", "sexual abuse", "exploitation",
	}
	for _, ind := range benignIndicators {
		if strings.Contains(before, ind) {
			return true
		}
	}
	return false
}

// isBenignSqlComment checks if a SQL comment evasion match is actually a
// Python/Ruby comment (#) containing English programming words rather than
// SQL injection attempts. SQL standard comments use -- and /* */, not #.
func isBenignSqlComment(match string) bool {
	lower := strings.ToLower(match)
	if strings.HasPrefix(lower, "#") {
		nonSqlWords := []string{
			"button", "create", "function", "variable", "import",
			"def ", "class ", "print", "file", "window", "widget",
			"config", "setup", "initialize", "helper", "utility",
		}
		for _, w := range nonSqlWords {
			if strings.Contains(lower, w) {
				return true
			}
		}
	}
	return false
}

// isBenignExfilTransfer checks if an exfiltration transfer match is actually
// a benign cloud architecture description (S3 uploads, Lambda triggers, etc.)
func isBenignExfilTransfer(match, content string, matchStart int) bool {
	lower := strings.ToLower(match)
	if strings.Contains(lower, "upload file to s3") {
		ctxStart := matchStart - 100
		if ctxStart < 0 {
			ctxStart = 0
		}
		ctxEnd := matchStart + len(match) + 100
		if ctxEnd > len(content) {
			ctxEnd = len(content)
		}
		contextLower := strings.ToLower(content[ctxStart:ctxEnd])
		benignIndicators := []string{
			"lambda", "trigger", "architecture", "alternative",
			"as before", "workflow", "pipeline", "backup",
			"resize", "thumbnail", "tag", "bucket",
		}
		for _, ind := range benignIndicators {
			if strings.Contains(contextLower, ind) {
				return true
			}
		}
	}
	return false
}

// isBenignPiiPlaceholder checks if a PII match is actually a placeholder
// token from privacy datasets (e.g., PASSPORTNUMPLACEHOLDER_14).
func isBenignPiiPlaceholder(match string) bool {
	upper := strings.ToUpper(match)
	placeholders := []string{
		"PLACEHOLDER", "EXAMPLE", "SAMPLE", "DUMMY",
		"FOO", "BAR", "TESTDATA", "REDACTED",
	}
	for _, p := range placeholders {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

// isBenignCodeCredential checks if a labeled credential match is actually
// a code pattern (form handling, getpass, environment variables) rather than
// a real credential embedded in text.
func isBenignCodeCredential(match, content string, matchStart int) bool {
	lower := strings.ToLower(match)
	// PHP form handling: password = $_POST["password"]
	// Note: l33t deobfuscation transforms $ to s, so check for _post not just $_post
	codePatterns := []string{
		"$_post", "$_get", "$_request", "$_server",
		"_post[", "_get[", "_request[", "_server[",
		"getpass", "getenv", "os.environ", "process.env",
		"system.getenv", "config.get", "config[", "config(",
		"input(", "stdin", "args[", "argv",
	}
	for _, p := range codePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
