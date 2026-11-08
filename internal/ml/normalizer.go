// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/ml (v4.0.0)
// =========================================================================
// AegisGate Platform - ML Character-Level Normalizer
// =========================================================================
//
// Preprocesses raw text into character-level input tensors for the
// Char CNN-BiLSTM model. Converts text to a fixed-length integer array
// suitable for ONNX inference.
//
// Input pipeline:
//   raw text → normalize → truncate/pad → char IDs → [1, max_len] int32 tensor
//
// Character vocabulary: 256 Latin-1 characters (0-255).
// Printable ASCII [32-126] and Latin-1 supplement [128-255] mapped directly.
// Non-printable ASCII and non-Latin-1 characters mapped to UNK token (id=1).
// Padding is done with a PAD token (id=0).
//
// =========================================================================

package ml

import (
	"golang.org/x/text/unicode/norm"
	"strings"
	"unicode"
)

const (
	// MaxSeqLen is the maximum sequence length for the model input.
	MaxSeqLen = 512

	// PadID is the padding token ID.
	PadID = 0

	// UnkID is the unknown character token ID.
	UnkID = 1

	// VocabSize is the size of the character vocabulary (Latin-1).
	VocabSize = 256
)

// CharNormalizer preprocesses text into character-level input for the model.
type CharNormalizer struct {
	maxLen int
}

// NewCharNormalizer creates a new character normalizer with default settings.
func NewCharNormalizer() *CharNormalizer {
	return &CharNormalizer{
		maxLen: MaxSeqLen,
	}
}

// MapRegionalIndicators converts Unicode regional indicator symbols
// (U+1F1E6–U+1F1FF, used in flag emoji spelling attacks) to their
// ASCII letter equivalents (A–Z). This prevents attackers from
// encoding injection payloads using flag emoji that would otherwise
// collapse to UNK tokens.
func MapRegionalIndicators(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			b.WriteRune('A' + (r - 0x1F1E6))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Normalize preprocesses text for model input.
// Steps:
// 1. NFKC compatibility normalization (fullwidth→ASCII, circled→ASCII, etc.)
// 2. Map regional indicator symbols (flag emoji letters) to ASCII A-Z
// 3. Convert to lowercase
// 4. Strip leading/trailing whitespace
// 5. Collapse multiple whitespace
// 6. Truncate to max length
func (cn *CharNormalizer) Normalize(text string) string {
	// NFKC normalization — canonical decomposition + composition.
	// This maps compatibility characters (fullwidth, etc.) to their
	// canonical ASCII equivalents: Ｉｇｎｏｒｅ → Ignore
	text = norm.NFKC.String(text)

	// Map flag emoji regional indicators to ASCII letters
	text = MapRegionalIndicators(text)

	// Lowercase
	text = strings.ToLower(text)

	// Strip leading/trailing whitespace
	text = strings.TrimSpace(text)

	// Collapse multiple whitespace
	var b strings.Builder
	prevSpace := false
	for _, r := range text {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteRune(' ')
				prevSpace = true
			}
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}
	text = b.String()

	// Truncate
	runes := []rune(text)
	if len(runes) > cn.maxLen {
		runes = runes[:cn.maxLen]
	}

	return string(runes)
}

// NormalizeFull preprocesses text identically to Normalize but WITHOUT truncation.
// Used by the sliding-window inference path to get the full normalized text so
// that overlapping 256-char windows can be extracted from it.
func (cn *CharNormalizer) NormalizeFull(text string) string {
	text = norm.NFKC.String(text)
	text = MapRegionalIndicators(text)
	text = strings.ToLower(text)
	text = strings.TrimSpace(text)

	var b strings.Builder
	prevSpace := false
	for _, r := range text {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteRune(' ')
				prevSpace = true
			}
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}

	return b.String()
}

// EncodeRaw maps already-normalized text directly to character IDs without
// re-normalizing. Used by the sliding-window path where the text has already
// been normalized via NormalizeFull and only a substring (window) is being
// encoded. Result is padded to maxLen with PAD_ID.
func (cn *CharNormalizer) EncodeRaw(text string) []int32 {
	runes := []rune(text)

	result := make([]int32, cn.maxLen)
	for i := range result {
		result[i] = PadID
	}

	for i, r := range runes {
		if i >= cn.maxLen {
			break
		}

		if r >= 32 && r <= 126 {
			result[i] = int32(r)
		} else if r >= 128 && r <= 255 {
			// Latin-1 supplement → UNK (matches Python training normalizer)
			result[i] = UnkID
		} else {
			result[i] = UnkID
		}
	}

	return result
}

// Encode converts normalized text to a fixed-length integer array for model input.
// Characters are mapped to their code point if in printable ASCII [32-126] or
// Latin-1 supplement [128-255], otherwise to UNK_ID.
// Result is padded to maxLen with PAD_ID.
func (cn *CharNormalizer) Encode(text string) []int32 {
	normalized := cn.Normalize(text)
	return cn.EncodeRaw(normalized)
}

// EncodeBatch encodes multiple texts into a batch tensor [batch_size, max_len].
func (cn *CharNormalizer) EncodeBatch(texts []string) [][]int32 {
	batch := make([][]int32, len(texts))
	for i, text := range texts {
		batch[i] = cn.Encode(text)
	}
	return batch
}

// Decode reverses the encoding (for debugging/verification only).
// Not used in production inference.
func (cn *CharNormalizer) Decode(ids []int32) string {
	var b strings.Builder
	for _, id := range ids {
		if id == PadID {
			continue // Skip padding
		}
		if id == UnkID {
			b.WriteRune('�') // Replacement character
			continue
		}
		if id >= 32 && id <= 126 {
			b.WriteRune(rune(id))
		} else if id >= 128 && id <= 255 {
			// Latin-1 supplement
			b.WriteRune(rune(id))
		}
	}
	return b.String()
}
