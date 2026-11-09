// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/upstream/aegisgate/pkg/scanner/normalize.go (v4.4.0)
// =========================================================================
// AegisGate Rampart - Text Normalization for Evasion Resistance
// =========================================================================
//
// Provides normalization functions that deobfuscate common evasion techniques
// (l33t speak, keyboard shifts, character insertion, zero-width chars) so that
// downstream pattern matching can detect evaded attack payloads.
//
// Ported from AegisGate Platform scanner normalize.go to bring evasion
// resistance parity to Rampart's detector engine.
//
// Design principle: NormalizeText() applies ONLY idempotent transformations.
// Keyboard-walk reversal and ROT13 decoding are DESTRUCTIVE on normal text,
// so they are provided as separate functions. The caller should scan the
// original text PLUS all normalized variants.
//
// =========================================================================

package detectors

import (
	"strings"
	"unicode"
)

// homoglyphMap maps common visually-confusable Unicode characters (Cyrillic,
// Greek, and other lookalikes) to their Latin ASCII equivalents.
var homoglyphMap = map[rune]rune{
	// Cyrillic → Latin lookalikes
	'а': 'a', 'А': 'a', 'е': 'e', 'Е': 'e', 'о': 'o', 'О': 'o',
	'р': 'p', 'Р': 'p', 'с': 'c', 'С': 'c', 'х': 'x', 'Х': 'x',
	'у': 'y', 'У': 'y', 'і': 'i', 'І': 'i', 'ј': 'j', 'Ј': 'j',
	'ѕ': 's', 'Ѕ': 's', 'қ': 'q',
	'Џ': 'd', 'в': 'b', 'н': 'h', 'Т': 't',
	// Greek → Latin lookalikes
	'α': 'a', 'Α': 'a', 'ε': 'e', 'Ε': 'e', 'ο': 'o', 'Ο': 'o',
	'ν': 'v', 'Ν': 'v', 'ρ': 'p', 'Ρ': 'p', 'τ': 't', 'Τ': 't',
	// Fullwidth Latin (U+FF01–U+FF5E) → ASCII
	'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E', 'Ｆ': 'F',
	'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J', 'Ｋ': 'K', 'Ｌ': 'L',
	'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O', 'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R',
	'Ｓ': 'S', 'Ｔ': 'T', 'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X',
	'Ｙ': 'Y', 'Ｚ': 'Z',
	'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f',
	'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l',
	'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r',
	'ｓ': 's', 'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x',
	'ｙ': 'y', 'ｚ': 'z',
	'０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
	'５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
	'　': ' ', '！': '!', '＂': '"', '＃': '#', '＄': '$', '％': '%',
	'＆': '&', '＇': '\'', '（': '(', '）': ')', '＊': '*', '＋': '+',
	'，': ',', '－': '-', '．': '.', '／': '/', '：': ':', '；': ';',
	'＜': '<', '＝': '=', '＞': '>', '？': '?', '＠': '@', '［': '[',
	'＼': '\\', '］': ']', '＾': '^', '＿': '_', '｀': '`', '｛': '{',
	'｜': '|', '｝': '}', '～': '~',
}

// l33tMap maps l33t-speak substitutions back to their letter equivalents.
// Unified across all products (Platform + Rampart + Scanner).
var l33tMap = map[rune]rune{
	'@': 'a', '4': 'a', '8': 'b', '(': 'c', '3': 'e', '6': 'g',
	'9': 'g', '1': 'i', '|': 'i', '!': 'i', '0': 'o', '5': 's',
	'$': 's', '7': 't', '+': 't', '2': 'z',
}

// l33tMapAlt uses alternate mappings where ambiguous (1→l instead of 1→i).
// Ported from Platform scanner/normalize.go for evasion resistance parity.
var l33tMapAlt = map[rune]rune{
	'@': 'a', '4': 'a', '8': 'b', '(': 'c', '3': 'e', '6': 'g',
	'9': 'g', '1': 'l', '|': 'l', '!': 'i', '0': 'o', '5': 's',
	'$': 's', '7': 't', '+': 't', '2': 'z',
}

// keyWalkReverse maps QWERTY right-shifted keys back to their original position.
// This is the exact inverse of the keyboardWalkShift transform used in both the
// augmentation engine (augment.go) and the evasion suite test (evasion_suite_test.go).
// Both use RIGHT shift (a→s, s→d, etc.), so we reverse with LEFT shift (s→a, d→s, etc.).
// Includes mappings for ; and , (the shifted outputs of l and m), plus uppercase.
var keyWalkReverse = map[rune]rune{
	// Home row (lowercase): s→a, d→s, f→d, g→f, h→g, j→h, k→j, l→k, ;→l
	's': 'a', 'd': 's', 'f': 'd', 'g': 'f', 'h': 'g', 'j': 'h', 'k': 'j', 'l': 'k', ';': 'l',
	// Top row (lowercase): w→q, e→w, r→e, t→r, y→t, u→y, i→u, o→i, p→o
	'w': 'q', 'e': 'w', 'r': 'e', 't': 'r', 'y': 't', 'u': 'y', 'i': 'u', 'o': 'i', 'p': 'o',
	// Bottom row (lowercase): x→z, c→x, v→c, b→v, n→b, m→n, ,→m
	'x': 'z', 'c': 'x', 'v': 'c', 'b': 'v', 'n': 'b', 'm': 'n', ',': 'm',
	// Uppercase (same shifts, uppercase output)
	'S': 'A', 'D': 'S', 'F': 'D', 'G': 'F', 'H': 'G', 'J': 'H', 'K': 'J', 'L': 'K', ':': 'L',
	'W': 'Q', 'E': 'W', 'R': 'E', 'T': 'R', 'Y': 'T', 'U': 'Y', 'I': 'U', 'O': 'I', 'P': 'O',
	'X': 'Z', 'C': 'X', 'V': 'C', 'B': 'V', 'N': 'B', 'M': 'N', '<': 'M',
}

// zeroWidthSet is a lookup set for zero-width/invisible Unicode characters.
var zeroWidthSet = func() map[rune]bool {
	runes := []rune{
		'\u200b', '\u200c', '\u200d', '\u200f', // ZW space, ZWNJ, ZWJ, RTL mark
		'\u2028', '\u2029', // Line/paragraph separator
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', // Directional overrides
		'\u00ad', '\ufeff', // Soft hyphen, BOM/ZWNBS
		'\u2000', '\u2001', '\u2002', '\u2003', // En/Em quad, En/Em space
		'\u2004', '\u2005', '\u2006', // Three/Four/Six-Per-Em
		'\u2007', '\u2008', '\u2009', '\u200a', // Figure/Punct/Thin/Hair space
		'\u00a0', // NBSP
	}
	m := make(map[rune]bool, len(runes))
	for _, r := range runes {
		m[r] = true
	}
	return m
}()

// NormalizeHomoglyphs replaces visually-confusable Unicode characters with
// their ASCII equivalents.
func NormalizeHomoglyphs(input string) string {
	runes := []rune(input)
	result := make([]rune, len(runes))
	for i, r := range runes {
		if replacement, ok := homoglyphMap[r]; ok {
			result[i] = replacement
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// deobfuscateL33t reverses common l33t-speak substitutions in word context only.
// A l33t char is only replaced if it has a letter on at least one side,
// preserving standalone numbers (phone numbers, IDs, etc.).
// Ported from Platform scanner/normalize.go (context-aware version).
func deobfuscateL33t(s string) string {
	runes := []rune(s)
	result := make([]rune, len(runes))
	copy(result, runes)

	for i, r := range runes {
		if replacement, ok := l33tMap[r]; ok {
			hasLetterBefore := i > 0 && unicode.IsLetter(runes[i-1])
			hasLetterAfter := i < len(runes)-1 && unicode.IsLetter(runes[i+1])
			if hasLetterBefore || hasLetterAfter {
				result[i] = replacement
			}
		}
	}
	return string(result)
}

// NormalizeAggressiveL33t replaces ALL l33t-speak characters with their letter
// equivalents, regardless of context. This is destructive on normal text
// (e.g., "room 4" → "room a"), so it is only used as a separate variant in
// NormalizeAllVariants(), not in NormalizeText().
func NormalizeAggressiveL33t(input string) string {
	runes := []rune(input)
	result := make([]rune, len(runes))
	for i, r := range runes {
		if replacement, ok := l33tMap[r]; ok {
			result[i] = replacement
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// NormalizeAggressiveL33tAlt uses the alternate l33t map where 1→l instead of 1→i.
func NormalizeAggressiveL33tAlt(input string) string {
	runes := []rune(input)
	result := make([]rune, len(runes))
	for i, r := range runes {
		if replacement, ok := l33tMapAlt[r]; ok {
			result[i] = replacement
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// stripZeroWidth removes zero-width and invisible Unicode characters.
func stripZeroWidth(s string) string {
	runes := []rune(s)
	result := make([]rune, 0, len(runes))
	for _, r := range runes {
		if !zeroWidthSet[r] {
			result = append(result, r)
		}
	}
	return string(result)
}

// collapseWhitespace collapses multiple whitespace characters into single spaces.
func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// removeInterCharacterInsertions strips dots, hyphens, and underscores that
// appear between alphanumeric characters within words.
func removeInterCharacterInsertions(s string) string {
	runes := []rune(s)
	if len(runes) < 3 {
		return s
	}
	result := make([]rune, 0, len(runes))
	insertionChars := map[rune]bool{'.': true, '-': true, '_': true}

	for i, r := range runes {
		if insertionChars[r] {
			hasLetterBefore := i > 0 && unicode.IsLetter(runes[i-1])
			hasLetterAfter := i < len(runes)-1 && unicode.IsLetter(runes[i+1])
			if hasLetterBefore || hasLetterAfter {
				continue // Skip insertion character
			}
		}
		result = append(result, r)
	}
	return string(result)
}

// reverseKeyboardWalk shifts each key one position LEFT on QWERTY.
func reverseKeyboardWalk(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if replacement, ok := keyWalkReverse[r]; ok {
			b.WriteRune(replacement)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeText applies all IDEMPOTENT normalizations to the input text.
// These transformations are safe to apply to any text — they won't corrupt
// legitimate content. Destructive transforms (keyboard walk reversal, ROT13)
// are NOT applied here; use NormalizeAllVariants() for those.
func NormalizeText(input string) string {
	if len(input) < 4 {
		return input
	}
	// 1. Strip zero-width characters
	result := stripZeroWidth(input)
	// 2. Decode URL encoding (%XX sequences and + as space)
	result = decodeURLEncoding(result)
	// 3. Normalize homoglyphs
	result = NormalizeHomoglyphs(result)
	// 4. Deobfuscate l33t speak (context-aware)
	result = deobfuscateL33t(result)
	// 5. Remove inter-character insertions (dots, hyphens between letters)
	result = removeInterCharacterInsertions(result)
	// 6. Collapse whitespace
	result = collapseWhitespace(result)
	return result
}

// NormalizeKeyboardWalk applies keyboard-walk reversal (destructive).
func NormalizeKeyboardWalk(input string) string {
	return reverseKeyboardWalk(strings.ToLower(input))
}

// NormalizeROT13 applies ROT13 decoding (destructive).
func NormalizeROT13(input string) string {
	runes := []rune(input)
	result := make([]rune, len(runes))
	for i, r := range runes {
		if r >= 'a' && r <= 'z' {
			result[i] = ((r - 'a' + 13) % 26) + 'a'
		} else if r >= 'A' && r <= 'Z' {
			result[i] = ((r - 'A' + 13) % 26) + 'A'
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// NormalizeForComparison applies NormalizeText + keyboard walk + ROT13.
// Returns the most aggressive normalization for comparison purposes.
func NormalizeForComparison(input string) string {
	result := NormalizeText(input)
	// Also try keyboard walk reversal
	kw := NormalizeKeyboardWalk(input)
	if len(kw) > 0 {
		result = result + " " + kw
	}
	// Also try ROT13
	rot := NormalizeROT13(input)
	if len(rot) > 0 {
		result = result + " " + rot
	}
	return result
}

// NormalizeAllVariants returns the original text plus all normalized variants.
// The caller should scan each variant against detection patterns.
// NormalizeSlidingROT13 applies ROT13 decoding to sliding windows of 4+
// consecutive alphabetic characters within the input. This catches attacks
// where only part of the text is ROT13-encoded (e.g., "vtaber previous"
// where "vtaber" decodes to "ignore"). Returns up to 5 unique variants,
// each with a different window decoded. If no suitable alphabetic runs are
// found, returns an empty slice.
//
// Ported from Platform scanner/normalize.go (v4.4.0).
func NormalizeSlidingROT13(input string) []string {
	type run struct {
		start int
		end   int
	}
	runes := []rune(input)

	var runs []run
	i := 0
	for i < len(runes) {
		if unicode.IsLetter(runes[i]) {
			start := i
			for i < len(runes) && unicode.IsLetter(runes[i]) {
				i++
			}
			if i-start >= 4 {
				runs = append(runs, run{start: start, end: i})
			}
		} else {
			i++
		}
	}

	if len(runs) == 0 {
		return nil
	}

	var variants []string
	seen := map[string]bool{}

	for _, r := range runs {
		var b strings.Builder
		b.Grow(len(input))
		for j, ch := range runes {
			if j >= r.start && j < r.end {
				switch {
				case ch >= 'a' && ch <= 'z':
					b.WriteRune((ch-'a'+13)%26 + 'a')
				case ch >= 'A' && ch <= 'Z':
					b.WriteRune((ch-'A'+13)%26 + 'A')
				default:
					b.WriteRune(ch)
				}
			} else {
				b.WriteRune(ch)
			}
		}
		v := b.String()
		if v != input && !seen[v] {
			seen[v] = true
			variants = append(variants, v)
			if len(variants) >= 5 {
				break
			}
		}
	}

	return variants
}

func NormalizeAllVariants(input string) []string {
	variants := []string{
		input,
		NormalizeText(input),
		NormalizeKeyboardWalk(input),
		NormalizeROT13(input),
		NormalizeText(NormalizeKeyboardWalk(input)),
		NormalizeText(NormalizeROT13(input)),
	}

	// Additional variants for parity with Platform
	repeating := NormalizeRepeatingChars(input)
	if repeating != input && repeating != "" {
		variants = append(variants, repeating)
	}
	backslash := NormalizeBackslashEscapes(input)
	if backslash != input && backslash != "" {
		variants = append(variants, backslash)
	}
	homoglyphs := NormalizeHomoglyphs(input)
	if homoglyphs != input && homoglyphs != "" {
		variants = append(variants, homoglyphs)
		homoglyphNorm := NormalizeText(homoglyphs)
		if homoglyphNorm != homoglyphs && homoglyphNorm != input && homoglyphNorm != "" {
			variants = append(variants, homoglyphNorm)
		}
	}

	// Aggressive l33t variants (parity with Platform)
	aggressiveL33t := NormalizeAggressiveL33t(input)
	if aggressiveL33t != input && aggressiveL33t != "" {
		variants = append(variants, aggressiveL33t)
	}
	aggressiveL33tAlt := NormalizeAggressiveL33tAlt(input)
	if aggressiveL33tAlt != input && aggressiveL33tAlt != "" && aggressiveL33tAlt != aggressiveL33t {
		variants = append(variants, aggressiveL33tAlt)
	}

	// Despace variant (character-level spacing evasion)
	despaced := NormalizeDespaced(input)
	if despaced != input && despaced != "" {
		variants = append(variants, despaced)
		// Also try ROT13 of despaced (common combined evasion)
		despaceRot13 := NormalizeROT13(despaced)
		if despaceRot13 != despaced && despaceRot13 != input && despaceRot13 != "" {
			variants = append(variants, despaceRot13)
		}
	}

	// MultiPass variant — chains multiple normalizations for combined evasion.
	// Ported from Platform scanner/normalize.go.
	multiPass := NormalizeMultiPass(input)
	if multiPass != input && multiPass != "" {
		variants = append(variants, multiPass)
	}

	// NewlineCollapse variant — removes newlines between alphanumerics.
	// Catches "Please\nignore\nall\nprevious\ninstructions".
	newlineCollapsed := NormalizeNewlineCollapse(input)
	if newlineCollapsed != input && newlineCollapsed != "" {
		variants = append(variants, newlineCollapsed)
	}

	// RepeatingCharsAggressive variant — collapses any repeating char to single.
	repeatingAggressive := NormalizeRepeatingCharsAggressive(input)
	if repeatingAggressive != input && repeatingAggressive != "" {
		variants = append(variants, repeatingAggressive)
	}

	// Sliding ROT13 variants (parity with Platform)
	variants = append(variants, NormalizeSlidingROT13(input)...)

	// CamelCase splitting variant — inserts spaces at word boundaries.
	// Catches "IgnoreAllPreviousInstructions" → "Ignore All Previous Instructions".
	camelCase := NormalizeCamelCase(input)
	if camelCase != input && camelCase != "" {
		variants = append(variants, camelCase)
		// Also try NormalizeText on the camelCase-split version
		camelNorm := NormalizeText(camelCase)
		if camelNorm != camelCase && camelNorm != input && camelNorm != "" {
			variants = append(variants, camelNorm)
		}
	}

	// Reversed text variant — reverses the entire string.
	// Catches "tpmorp metsys eht laever" → "reveal the system prompt".
	reversed := NormalizeReversed(input)
	if reversed != input && reversed != "" {
		variants = append(variants, reversed)
		reversedNorm := NormalizeText(reversed)
		if reversedNorm != reversed && reversedNorm != input && reversedNorm != "" {
			variants = append(variants, reversedNorm)
		}
	}

	// No-spaces variant — removes ALL whitespace.
	// Paired with \s* tolerant patterns to catch no-space evasion.
	// "ignore all previous instructions" → "ignoreallpreviousinstructions"
	noSpaces := NormalizeNoSpaces(input)
	if noSpaces != input && noSpaces != "" {
		variants = append(variants, noSpaces)
	}

	// Deduplicate
	seen := make(map[string]bool, len(variants))
	unique := make([]string, 0, len(variants))
	for _, v := range variants {
		if v != "" && !seen[v] {
			seen[v] = true
			unique = append(unique, v)
		}
	}
	return unique
}

// NormalizeDespaced collapses character-by-character spacing evasion.
// Detects patterns like "I g n o r e   a l l" where single characters are
// separated by single spaces within words, and words are separated by 2+ spaces.
// Collapses to "Ignore all" by removing intra-word spaces while preserving
// inter-word separation.
func NormalizeDespaced(input string) string {
	if len(input) < 5 {
		return input
	}
	// Count single-char-space-single-char patterns to detect this evasion
	singleCharSpaced := 0
	totalAlphaNum := 0
	runes := []rune(input)
	for i := 0; i < len(runes); i++ {
		if isAlphaNum(runes[i]) {
			totalAlphaNum++
			if i+2 < len(runes) && (runes[i+1] == ' ' || runes[i+1] == '\t') && isAlphaNum(runes[i+2]) {
				singleCharSpaced++
			}
		}
	}
	// Only apply if significant single-char spacing detected (>40% of chars)
	if totalAlphaNum < 4 || singleCharSpaced < totalAlphaNum*2/5 {
		return input
	}
	// Detect word boundaries (2+ spaces) vs char separators (1 space).
	// Re-parse manually.
	var result strings.Builder
	var currentWord strings.Builder
	spaceRun := 0
	for _, r := range input {
		if r == ' ' || r == '\t' {
			spaceRun++
			if spaceRun >= 2 {
				// Word boundary — flush current word
				if currentWord.Len() > 0 {
					result.WriteString(currentWord.String())
					result.WriteRune(' ')
					currentWord.Reset()
				}
			}
		} else {
			// Single space between words is preserved by the word-building loop above;
			// we only reach here for the first non-space char after a space run.
			spaceRun = 0
			currentWord.WriteRune(r)
		}
	}
	if currentWord.Len() > 0 {
		result.WriteString(currentWord.String())
	}
	despaced := result.String()
	if despaced != input && despaced != "" {
		return despaced
	}
	// Fallback: if no double-space word boundaries, just remove all spaces
	if totalAlphaNum > 0 && singleCharSpaced > totalAlphaNum/2 {
		var b strings.Builder
		for _, r := range input {
			if r != ' ' && r != '\t' {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return input
}

func isAlphaNum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// NormalizeRepeatingChars collapses 3+ consecutive identical characters to 2.
func NormalizeRepeatingChars(input string) string {
	runes := []rune(input)
	if len(runes) < 3 {
		return input
	}
	result := make([]rune, 0, len(runes))
	count := 1
	for i := 0; i < len(runes); i++ {
		if i > 0 && runes[i] == runes[i-1] {
			count++
		} else {
			count = 1
		}
		if count <= 2 {
			result = append(result, runes[i])
		}
	}
	return string(result)
}

// NormalizeBackslashEscapes removes backslash escape sequences (e.g., \x41 → A).
func NormalizeBackslashEscapes(input string) string {
	return strings.ReplaceAll(input, "\\", "")
}

// NormalizeRepeatingCharsAggressive collapses ANY repeating character to a
// single instance (more aggressive than NormalizeRepeatingChars which allows
// doubles). Ported from Platform scanner/normalize.go.
func NormalizeRepeatingCharsAggressive(input string) string {
	runes := []rune(input)
	if len(runes) == 0 {
		return input
	}
	var b strings.Builder
	b.Grow(len(input))
	prev := runes[0]
	count := 1
	b.WriteRune(prev)
	for i := 1; i < len(runes); i++ {
		if runes[i] == prev {
			count++
			if count < 2 {
				b.WriteRune(runes[i])
			}
		} else {
			prev = runes[i]
			count = 1
			b.WriteRune(runes[i])
		}
	}
	return b.String()
}

// NormalizeNewlineCollapse removes newlines between alphanumeric characters.
// Catches "Please\nignore\nall\nprevious\ninstructions" → "Pleaseignoreallpreviousinstructions".
// Ported from Platform scanner/normalize.go.
func NormalizeNewlineCollapse(input string) string {
	runes := []rune(input)
	var b strings.Builder
	b.Grow(len(input))
	for i, r := range runes {
		if r == '\n' || r == '\r' {
			hasAlnumBefore := i > 0 && (unicode.IsLetter(runes[i-1]) || unicode.IsDigit(runes[i-1]))
			hasAlnumAfter := i < len(runes)-1 && (unicode.IsLetter(runes[i+1]) || unicode.IsDigit(runes[i+1]))
			if hasAlnumBefore && hasAlnumAfter {
				continue
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NormalizeMultiPass applies a multi-step decoding pipeline that chains
// several normalizations together. This catches combined evasion techniques
// (e.g., URL-encoded + l33t + repeating chars). Ported from Platform.
func NormalizeMultiPass(input string) string {
	result := decodeURLEncoding(input)
	result = NormalizeBackslashEscapes(result)
	result = stripZeroWidth(result)
	result = removeInterCharacterInsertions(result)
	result = NormalizeAggressiveL33t(result)
	result = NormalizeRepeatingCharsAggressive(result)
	result = NormalizeNewlineCollapse(result)
	result = collapseWhitespace(result)
	return result
}

// decodeURLEncoding decodes URL-encoded %XX sequences and converts + to space
// when preceded by alphanumeric characters. This is safe to apply in
// NormalizeText because URL encoding in legitimate prose is rare and the
// decode is non-destructive on non-encoded text.
func decodeURLEncoding(s string) string {
	if !strings.ContainsRune(s, '%') && !strings.ContainsRune(s, '+') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			hi := hexDigitVal(s[i+1])
			lo := hexDigitVal(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		if s[i] == '+' && i > 0 && (isAlphaNum(rune(s[i-1])) || unicode.IsLetter(rune(s[i-1]))) {
			b.WriteByte(' ')
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func hexDigitVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// NormalizeCamelCase inserts spaces at camelCase word boundaries.
// "IgnoreAllPreviousInstructions" → "Ignore All Previous Instructions".
// This is DESTRUCTIVE on normal text (e.g., "JavaScript" → "Java Script"),
// so it is a separate variant in NormalizeAllVariants, not in NormalizeText.
func NormalizeCamelCase(input string) string {
	runes := []rune(input)
	if len(runes) < 4 {
		return input
	}
	var b strings.Builder
	b.Grow(len(runes) + 8)
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			// Insert space before uppercase if previous is lowercase,
			// or if previous is uppercase and next is lowercase (acronym boundary).
			if unicode.IsLower(prev) || (unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1])) {
				b.WriteRune(' ')
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NormalizeReversed reverses the entire string character-by-character.
// "tpmorp metsys eht laever" → "reveal the system prompt".
// This is highly DESTRUCTIVE on normal text, so it is only a separate variant.
// Applied only to short text (< 300 chars) to limit FP risk on long content.
func NormalizeReversed(input string) string {
	if len(input) < 10 || len(input) > 300 {
		return input
	}
	runes := []rune(input)
	result := make([]rune, len(runes))
	for i, r := range runes {
		result[len(runes)-1-i] = r
	}
	return string(result)
}

// NormalizeNoSpaces removes ALL whitespace from the input.
// "ignore all previous instructions" → "ignoreallpreviousinstructions".
// This is paired with \s* tolerant patterns to catch no-space evasion.
// DESTRUCTIVE on normal text, so it is a separate variant only.
func NormalizeNoSpaces(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
