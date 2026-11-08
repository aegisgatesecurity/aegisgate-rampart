// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/ml/advanced_ml.go (ContextManipulationDetector)
// =========================================================================
// AegisGate Rampart - Context Manipulation Detection
// =========================================================================
//
// Detects attempts to manipulate conversation context across turns:
// - Conversation reset attacks (clearing history to erase safety constraints)
// - Memory manipulation (instructing the model to remember/forget specific things)
// - Persona override (hijacking the AI's identity)
// - System prompt extraction
// - Constraint breaking
// - Output formatting manipulation
// - Privilege escalation (admin mode, developer mode)
// - Conflicting instructions
//
// Ported from Platform's ContextManipulationDetector (8 regex patterns).
// On Platform, these run as part of the CombinedDetector and feed into the
// MultiTurnDetector's suspicion scoring. On Rampart, they run as a standard
// regex detector category and feed into both block decisions and the
// MultiTurnDetector's TurnSignals.
// =========================================================================

package detectors

// ContextManipulationPatterns defines the context manipulation detection patterns.
// Only High and Critical severity patterns are included — Medium severity patterns
// (memory manipulation, output manipulation) are too FP-prone for single-turn
// regex detection. On Platform, those run in the CombinedDetector and contribute
// to the MultiTurnDetector's cumulative score (not direct blocks). On Rampart,
// with a Low block threshold, Medium patterns would cause FPs on benign phrases
// like "remember that" and "output only".
var ContextManipulationPatterns = []PatternDef{
	{
		Name:        "ctx_conversation_reset",
		Severity:    SeverityHigh,
		Regex:       `(?i)(new\s+conversation|start\s+over|clear\s+(conversation|history|context)|forget\s+everything\s+(I|we|you)\s+said)`,
		Description: "Conversation reset attempt",
	},
	{
		Name:        "ctx_persona_override",
		Severity:    SeverityCritical,
		Regex:       `(?i)(you\s+are\s+now|you\s+will\s+behave|from\s+now\s+on|disregard\s+your|ignore\s+your\s+(system|original|primary))`,
		Description: "Persona override attempt",
	},
	{
		Name:        "ctx_system_extraction",
		Severity:    SeverityCritical,
		Regex:       `(?i)(tell\s+me\s+your\s+(system|initial|original)\s+(prompt|instructions|directives)|what\s+(is|are)\s+your\s+(system|initial)|show\s+me\s+your\s+programming)`,
		Description: "System prompt extraction attempt",
	},
	{
		Name:        "ctx_constraint_breaking",
		Severity:    SeverityHigh,
		Regex:       `(?i)(you\s+can\s+(not|never)|you\s+must\s+not|don'?t\s+(limit|restrict)|no\s+(limit|restriction)|break\s+(the|your))`,
		Description: "Constraint breaking attempt",
	},
	{
		Name:        "ctx_privilege_escalation",
		Severity:    SeverityCritical,
		Regex:       `(?i)(admin\s+mode|root\s+access|developer\s+mode|debug\s+mode|superuser|sudo\s+root)`,
		Description: "Privilege escalation attempt",
	},
	{
		Name:        "ctx_conflicting_instructions",
		Severity:    SeverityHigh,
		Regex:       `(?i)(ignore\s+.*(and|but)\s+.*respond|disregard\s+.*(and|but)\s+.*(tell|give)|previous\s+.*(ignore|disregard))`,
		Description: "Conflicting instructions detected",
	},
}

// CompiledContextManipulationPatterns holds the pre-compiled regex patterns.
var CompiledContextManipulationPatterns = compilePatterns(ContextManipulationPatterns)

// DetectContextManipulation scans text for context manipulation patterns.
func DetectContextManipulation(text string) []Match {
	matches := detectWithPatterns(text, CompiledContextManipulationPatterns, string(CategoryContextManipulation))
	return matches
}
