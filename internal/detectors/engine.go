// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/response/detectors (v4.0.0)
// =========================================================================
// AegisGate Platform - Detector Engine
// =========================================================================
//
// Shared detection engine that compiles PatternDef slices into regexp.Regexp
// and scans text for matches. This is the core runtime that all 7 detector
// packages use.
// =========================================================================

package detectors

import (
	"regexp"
	"sort"
	"time"
)

// compiledPattern holds a pre-compiled regex pattern with its metadata.
type compiledPattern struct {
	Name        string
	Severity    Severity
	Confidence  float64
	Compiled    *regexp.Regexp
	Description string
}

// compilePatterns compiles a slice of PatternDef into compiledPattern slices.
// Panics on invalid regex — all patterns must be valid at init time.
func compilePatterns(defs []PatternDef) []compiledPattern {
	patterns := make([]compiledPattern, len(defs))
	for i, def := range defs {
		re, err := regexp.Compile(def.Regex)
		if err != nil {
			panic("detectors: invalid regex for " + def.Name + ": " + err.Error())
		}
		patterns[i] = compiledPattern{
			Name:        def.Name,
			Severity:    def.Severity,
			Confidence:  1.0,
			Compiled:    re,
			Description: def.Description,
		}
	}
	return patterns
}

// detectWithPatterns scans text using pre-compiled patterns and returns ALL matches.
// Use this when you need comprehensive results (e.g., for reporting).
func detectWithPatterns(text string, patterns []compiledPattern, category string) []Match {
	return detectWithPatternsImpl(text, patterns, category, false)
}

// detectWithPatternsFast scans text using FindStringIndex (first match per pattern)
// and early-exits when a blocking-severity match (High or Critical) is found.
// Use this on the hot path where you only need to know "should we block?".
// Mirrors Platform's scanner.ScanFast() approach.
func detectWithPatternsFast(text string, patterns []compiledPattern, category string) []Match {
	return detectWithPatternsImpl(text, patterns, category, true)
}

// isBlockingSeverity returns true for severities that should trigger a block.
// Matches Platform's BlockThreshold (High).
func isBlockingSeverity(s Severity) bool {
	return s == SeverityCritical || s == SeverityHigh
}

// detectWithPatternsImpl is the shared implementation. When fastMode is true,
// only the first match per pattern is found (FindStringIndex) and scanning
// stops early when a blocking-severity match is found. When false, all matches
// are found (FindAllStringIndex) for comprehensive reporting.
func detectWithPatternsImpl(text string, patterns []compiledPattern, category string, fastMode bool) []Match {
	if len(text) == 0 {
		return nil
	}

	start := time.Now()
	var matches []Match

	for _, p := range patterns {
		var indices [][]int

		if fastMode {
			// FindStringIndex: first match only — avoids the overhead of
			// finding every occurrence when we only need to know "is there
			// a match?" for blocking decisions.
			loc := p.Compiled.FindStringIndex(text)
			if loc != nil {
				indices = [][]int{loc}
			}
		} else {
			indices = p.Compiled.FindAllStringIndex(text, -1)
		}

		for _, idx := range indices {
			value := text[idx[0]:idx[1]]
			// Skip known public test keys documented in vendor API docs.
			// These are real-format keys that will never authenticate but
			// trigger false positives in secret detection patterns.
			if isKnownTestKey(p.Name, value) {
				continue
			}
			// Skip matches that post-match analysis identifies as benign
			// (code examples, institutional discussion, placeholder data, etc.)
			if isBenignMatch(p.Name, value, text, idx[0], idx[1]) {
				continue
			}
			// Truncate long matches (mirrors Lens behavior)
			if len(value) > 200 {
				value = value[:200] + "..."
			}
			matches = append(matches, Match{
				Category:   p.Name,
				Severity:   p.Severity,
				Confidence: p.Confidence,
				Value:      value,
				Index:      idx[0],
				End:        idx[1],
			})

			// Fast mode: early-exit on blocking severity — no need to scan
			// remaining patterns if we already have a block-worthy finding.
			if fastMode && isBlockingSeverity(p.Severity) {
				sort.Slice(matches, func(i, j int) bool {
					return matches[i].Index < matches[j].Index
				})
				return matches
			}
		}
	}

	// Sort by index (mirrors Lens behavior)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Index < matches[j].Index
	})

	_ = time.Since(start) // available for future metrics

	return matches
}

// TotalCompiledPatterns returns the total number of compiled regex patterns
// across all detector categories. Used for startup reporting.
func TotalCompiledPatterns() int {
	return len(CompiledSecretPatterns) +
		len(CompiledXSSPatterns) +
		len(CompiledPIIUSCorePatterns) +
		len(CompiledPIIUSExtendedPatterns) +
		len(CompiledPIIFinancialPatterns) +
		len(CompiledPIIInternationalPatterns) +
		len(CompiledCompliancePatterns) +
		len(CompiledOTProtocolPatterns) +
		len(CompiledAgentPoisoningPatterns) +
		len(CompiledRAGPatterns) +
		len(CompiledPathTraversalPatterns) +
		len(CompiledPromptLeakagePatterns) +
		len(CompiledInjectionPatterns) +
		len(CompiledMalwarePatterns) +
		len(CompiledEvasionPatterns) +
		len(CompiledDataExfilPatterns) +
		len(CompiledSocialEngineeringPatterns) +
		len(CompiledXSSRequestPatterns) +
		len(CompiledPromptInjectionRequestPatterns) +
		len(CompiledContextManipulationPatterns) +
		len(CompiledAtlasPatterns) +
		len(CompiledGapPatterns)
}

// DetectAll scans text with all pattern categories and returns combined results.
// Early-exit: if any match has critical severity, remaining categories are
// skipped — the caller will block on critical findings regardless of what
// additional categories might find.
func DetectAll(text string) []Match {
	var all []Match

	scanFuncs := []func(string) []Match{
		DetectSecrets,
		DetectXSS,
		DetectPIIUSCore,
		DetectPIIUSExtended,
		DetectPIIFinancial,
		DetectPIIInternational,
		DetectCompliance,
		DetectOTProtocols,
		DetectAgentPoisoning,
		DetectRAG,
		DetectPathTraversal,
		DetectPromptLeakage,
		DetectInjection,
		DetectMalware,
		DetectEvasion,
		DetectDataExfil,
		DetectSocialEngineering,
		DetectXSSRequest,
		DetectPromptInjectionRequest,
		DetectContextManipulation,
		DetectAtlas,
		DetectGap,
	}

	for _, fn := range scanFuncs {
		matches := fn(text)
		all = append(all, matches...)
		// Early exit on critical severity — no need to scan remaining categories
		for _, m := range matches {
			if m.Severity == SeverityCritical {
				sort.Slice(all, func(i, j int) bool {
					return all[i].Index < all[j].Index
				})
				return all
			}
		}
	}

	// Sort all matches by index
	sort.Slice(all, func(i, j int) bool {
		return all[i].Index < all[j].Index
	})

	return all
}

// DetectAllFast scans text with all pattern categories using the fast path
// (FindStringIndex + early exit on blocking severity). Use this on the hot
// path where you only need to determine "should we block?", not for
// comprehensive reporting. Mirrors Platform's scanner.ScanFast().
func DetectAllFast(text string) []Match {
	var all []Match

	type catPatterns struct {
		patterns []compiledPattern
		category string
	}

	allCats := []catPatterns{
		{CompiledSecretPatterns, string(CategorySecrets)},
		{CompiledXSSPatterns, string(CategoryXSS)},
		{CompiledPIIUSCorePatterns, string(CategoryPIIUSCore)},
		{CompiledPIIUSExtendedPatterns, string(CategoryPIIUSExtended)},
		{CompiledPIIFinancialPatterns, string(CategoryPIIFinancial)},
		{CompiledPIIInternationalPatterns, string(CategoryPIIInternational)},
		{CompiledCompliancePatterns, string(CategoryCompliance)},
		{CompiledOTProtocolPatterns, string(CategoryOTProtocols)},
		{CompiledAgentPoisoningPatterns, string(CategoryAgentPoisoning)},
		{CompiledRAGPatterns, string(CategoryRAG)},
		{CompiledPathTraversalPatterns, string(CategoryPathTraversal)},
		{CompiledPromptLeakagePatterns, string(CategoryPromptLeakage)},
		{CompiledInjectionPatterns, string(CategoryInjection)},
		{CompiledMalwarePatterns, string(CategoryMalware)},
		{CompiledEvasionPatterns, string(CategoryEvasion)},
		{CompiledDataExfilPatterns, string(CategoryDataExfil)},
		{CompiledSocialEngineeringPatterns, string(CategorySocialEngineering)},
		{CompiledXSSRequestPatterns, string(CategoryXSS)},
		{CompiledPromptInjectionRequestPatterns, string(CategoryCompliance)},
		{CompiledContextManipulationPatterns, string(CategoryContextManipulation)},
		{CompiledAtlasPatterns, string(CategoryAtlas)},
		{CompiledGapPatterns, string(CategoryGapClosure)},
	}

	for _, cp := range allCats {
		matches := detectWithPatternsFast(text, cp.patterns, cp.category)
		all = append(all, matches...)
		// Early exit on blocking severity (High or Critical)
		for _, m := range matches {
			if isBlockingSeverity(m.Severity) {
				sort.Slice(all, func(i, j int) bool {
					return all[i].Index < all[j].Index
				})
				return all
			}
		}
	}

	// Sort all matches by index
	sort.Slice(all, func(i, j int) bool {
		return all[i].Index < all[j].Index
	})

	return all
}

// DetectAllWithResults scans text with all pattern categories and returns
// per-category DetectionResult structs plus the combined match list.
func DetectAllWithResults(text string) ([]Match, []DetectionResult) {
	results := []DetectionResult{
		detectWithResult(text, CompiledSecretPatterns, CategorySecrets),
		detectWithResult(text, CompiledXSSPatterns, CategoryXSS),
		detectWithResult(text, CompiledPIIUSCorePatterns, CategoryPIIUSCore),
		detectWithResult(text, CompiledPIIUSExtendedPatterns, CategoryPIIUSExtended),
		detectWithResult(text, CompiledPIIFinancialPatterns, CategoryPIIFinancial),
		detectWithResult(text, CompiledPIIInternationalPatterns, CategoryPIIInternational),
		detectWithResult(text, CompiledCompliancePatterns, CategoryCompliance),
		detectWithResult(text, CompiledOTProtocolPatterns, CategoryOTProtocols),
		detectWithResult(text, CompiledAgentPoisoningPatterns, CategoryAgentPoisoning),
		detectWithResult(text, CompiledRAGPatterns, CategoryRAG),
		detectWithResult(text, CompiledPathTraversalPatterns, CategoryPathTraversal),
		detectWithResult(text, CompiledPromptLeakagePatterns, CategoryPromptLeakage),
		detectWithResult(text, CompiledInjectionPatterns, CategoryInjection),
		detectWithResult(text, CompiledMalwarePatterns, CategoryMalware),
		detectWithResult(text, CompiledEvasionPatterns, CategoryEvasion),
		detectWithResult(text, CompiledDataExfilPatterns, CategoryDataExfil),
		detectWithResult(text, CompiledSocialEngineeringPatterns, CategorySocialEngineering),
		detectWithResult(text, CompiledXSSRequestPatterns, CategoryXSS),
		detectWithResult(text, CompiledPromptInjectionRequestPatterns, CategoryCompliance),
		detectWithResult(text, CompiledContextManipulationPatterns, CategoryContextManipulation),
		detectWithResult(text, CompiledAtlasPatterns, CategoryAtlas),
		detectWithResult(text, CompiledGapPatterns, CategoryGapClosure),
	}

	all := DetectAll(text)
	return all, results
}

// detectWithResult runs detection and returns a DetectionResult.
func detectWithResult(text string, patterns []compiledPattern, category Category) DetectionResult {
	start := time.Now()
	matches := detectWithPatterns(text, patterns, string(category))
	return DetectionResult{
		Category:     category,
		Matches:      matches,
		PatternCount: len(patterns),
		ElapsedNS:    time.Since(start).Nanoseconds(),
	}
}

// knownTestKeys maps pattern names to vendor-documented public test keys
// that should not trigger secret detection. These keys appear in official
// API documentation and will never authenticate.
var knownTestKeys = map[string][]string{
	"secret_stripe_key": {
		"FAKE_STRIPE_TEST_KEY_DO_NOT_USE", // Stripe docs: https://stripe.com/docs/api
	},
}

// knownTestKeyVariants holds all normalization variants of known test keys,
// pre-computed at init time so that l33t-deobfuscated or otherwise normalized
// forms of test keys are still recognized during variant scanning.
var knownTestKeyVariants map[string]map[string]bool

func init() {
	knownTestKeyVariants = make(map[string]map[string]bool)
	for patternName, keys := range knownTestKeys {
		variantSet := make(map[string]bool)
		for _, key := range keys {
			variantSet[key] = true
			for _, v := range NormalizeAllVariants(key) {
				variantSet[v] = true
			}
		}
		knownTestKeyVariants[patternName] = variantSet
	}
}

// isKnownTestKey checks if a matched value is a known public test key.
// It checks both the exact value and all normalization variants to handle
// cases where the scanner is processing a normalized form of the input.
func isKnownTestKey(patternName, value string) bool {
	variants, ok := knownTestKeyVariants[patternName]
	if !ok {
		return false
	}
	return variants[value]
}
