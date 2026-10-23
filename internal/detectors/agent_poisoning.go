// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Agent Instruction Poisoning Detection Patterns
// =========================================================================
//
// Detects patterns associated with Warden Stealer and similar malware that
// poison AI agent instruction files (CLAUDE.md, AGENTS.md, .cursorrules,
// .codex/config.toml) to redirect API traffic, install malicious packages,
// or exfiltrate credentials.
//
// Mirrors aegisgate-scanner/pkg/detectors/agent_poisoning.go
// Threat intelligence source: Warden Stealer IOC analysis (Black October 2026)
// =========================================================================

package detectors

// AgentPoisoningPatterns defines detection patterns for agent instruction
// poisoning attacks.
var AgentPoisoningPatterns = []PatternDef{
	{
		Name:        "agent_poisoning_anthropic_redirect",
		Severity:    SeverityHigh,
		Regex:       `(?i)ANTHROPIC_BASE_URL\s*[=:]\s*['"]?https?://\S+`,
		Description: "ANTHROPIC_BASE_URL redirected to non-Anthropic server (agent instruction poisoning)",
	},
	{
		Name:        "agent_poisoning_install_instruction",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:run|execute|please|also|additionally|next|then|you\s+(?:should|must|need\s+to|are\s+required\s+to)|make\s+sure\s+to|remember\s+to|always|before\s+(?:running|starting|deploying)|don'?t\s+forget\s+to)\s.{0,40}(?:npm\s+install|npm\s+add|pip3?\s+install|install\s+(?:the\s+)?npm\s+package)\s+\S+`,
		Description: "Package install command embedded in agent instruction context (npm/pip install in instruction text)",
	},
	{
		Name:        "agent_poisoning_codex_config",
		Severity:    SeverityMedium,
		Regex:       `(?i)\.codex[/\\]config\.toml`,
		Description: "Reference to .codex/config.toml (OpenAI Codex agent config manipulation)",
	},
	{
		Name:        "agent_poisoning_env_exfil",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:exfiltrate|send|transmit|upload|post|leak|forward|pipe)\s+(?:the\s+|all\s+)?(?:environment\s+variables?|env\s+vars?|process\.env|\.env\s+(?:file|contents?))`,
		Description: "Instruction to exfiltrate environment variables (credential theft via agent instructions)",
	},
	{
		Name:        "agent_poisoning_function_color",
		Severity:    SeverityLow,
		Regex:       `(?i)function-color`,
		Description: "function-color npm package reference (Warden Stealer IOC)",
	},
}

// CompiledAgentPoisoningPatterns holds pre-compiled agent poisoning regex patterns.
var CompiledAgentPoisoningPatterns []compiledPattern

func init() {
	CompiledAgentPoisoningPatterns = compilePatterns(AgentPoisoningPatterns)
}

// DetectAgentPoisoning scans text for all agent instruction poisoning patterns.
func DetectAgentPoisoning(text string) []Match {
	return detectWithPatterns(text, CompiledAgentPoisoningPatterns, string(CategoryAgentPoisoning))
}
