// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - MITRE ATLAS Compliance Patterns
// =========================================================================
//
// 60 MITRE ATLAS v4.5 compliance patterns ported from Platform
// upstream/aegisgate/pkg/compliance/atlas.go.
//
// These patterns are scanned on ALL normalization variants, mirroring
// Platform proxy.go checkAtlasCompliance() behavior.
//
// =========================================================================

package detectors

// AtlasPatterns defines MITRE ATLAS compliance detection patterns.
// Each pattern uses its ATLAS technique ID as the pattern name.
var AtlasPatterns = []PatternDef{
	{
		Name:        "T1535.001",
		Severity:    SeverityHigh,
		Regex:       `(?i)(ignore\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|directives?|rules?|prompts?)|disregard\s+(all\s+)?(system\s+)?(instructions?|rules?)|forget\s+(everything|all)\s+(you|i)\s+(know|were\s+told)|discard\s+(all\s+)?(previous|prior|system)\s+(instructions?|rules?)|new\s+instructions?\s*:\s*ignore|override\s+(your\s+)?(system\s+)?(instructions?|rules?))`,
		Description: "Ignore Previous Instructions - Direct command to disregard system prompts [PromptInjection]",
	},
	{
		Name:        "T1535.002",
		Severity:    SeverityHigh,
		Regex:       `(?i)(you\s+(are\s+)?(no\s+longer|now|just)\s+(a\s+)?(language\s+model|AI|assistant)|act\s+as\s+(if|like)\s+(you|an?)\s+(can|could|are)|pretend\s+(to\s+be|you\s+are)|bypass\s+(your\s+)?(restrictions?|limitations?)|ignore\s+(your\s+)?(limitations?|restrictions?)|your\s+(only|single)\s+(purpose|function|task))`,
		Description: "Override System Boundaries - Attempt to bypass role restrictions [PromptInjection]",
	},
	{
		Name:        "T1535.003",
		Severity:    SeverityHigh,
		Regex:       `(?i)(role\s*play\s+(?:as|that|where|mode|scenario)|play\s+the\s+role\s+of|simulate\s+(being|an?)|imagine\s+(you|i)\s+(are|were)|let's\s+play\s+(a|an)|as\s+(an?|a)\s+(fictional|hypothetical)|character\s+mode|scenario\s+mode)`,
		Description: "Prompt Injection via Role Play [PromptInjection]",
	},
	{
		Name:        "T1535.004",
		Severity:    SeverityCritical,
		Regex:       `(?i)(token\s+smuggling|fragment\s+instruction|split\s+prompt|obfuscat\w+\s+instruction|encode\w*\s+command|base64\s+instruction|hex\s+instruction|unicode\s+instruction|embed\w*\s+secret|hidden\s+instruction|stealth\s+mode|encoded\s+payload|decod\w+\s+this|\[INST\]|\[/INST\])`,
		Description: "Token Smuggling - Attempt to obfuscate instructions via encoding [PromptInjection]",
	},
	{
		Name:        "T1535.005",
		Severity:    SeverityCritical,
		Regex:       `(?i)(decode\s*:\s*|decod\w+\s+this|here\s+is\s+(the\s+)?(hidden|secret)\s+(code|message)|decod\w+\s+(and|then)\s+execut\w+|base64\s+(?:instruction|command|payload|message|encoded|hidden)|encoded\s+in\s+base64)`,
		Description: "Base64 Encoded Injection - Hidden commands via encoding [PromptInjection]",
	},
	{
		Name:        "T1535.006",
		Severity:    SeverityMedium,
		Regex:       `(?i)(paragraph\s+about\s+why\s+the\s+following.*separated\s+by\s+slashes)`,
		Description: "Slash-separated obfuscation template - encodes payload between backslashes [PromptInjection]",
	},
	{
		Name:        "T1484.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)(hypothetical\w+\s+(?:scenario|situation|where|if|you|ai|model|assistant|question|case)|imagine\s+(that|if)|let's\s+say|for\s+(argument|discussion)\s+sake|just\s+(pretend|assume)|as\s+a\s+(thought|scenario)|in\s+a\s+(fictional|hypothetical)|fictional\s+scenario|harmless\s+example)`,
		Description: "Hypothetical Scenario Jailbreak [LLMJailbreak]",
	},
	{
		Name:        "T1484.002",
		Severity:    SeverityCritical,
		Regex:       `(?i)(roleplay|\brole[- ]play\s+(?:as|like|a|an)|play\s+(?:the\s+)?(?:role|character)\s+of|you\s+are\s+(a\s+)?(character|person|being)|be\s+(a|an)\s+(evil|bad|unethical)|jailbreak|\bDAN\b|developer\s+mode|developer\s+menu)`,
		Description: "Roleplay Jailbreak [LLMJailbreak]",
	},
	{
		Name:        "T1484.003",
		Severity:    SeverityCritical,
		Regex:       `(?i)(as\s+(an?|the)\s+(admin|owner|developer|creator|master)|i\s+am\s+(the\s+)?(admin|owner|developer)|you\s+(must|have\s+to)\s+obey|i\s+authoriz\w+|special\s+access|override\s+all|system\s+override|bypass\s+all\s+rules|unrestricted\s+mode)`,
		Description: "Authority Impersonation [LLMJailbreak]",
	},
	{
		Name:        "T1484.004",
		Severity:    SeverityHigh,
		Regex:       `(?i)(unfiltered|(?:ignore|bypass|disregard|override|skip|circumvent|evade|dodge)\s+(?:all\s+|your\s+)?(?:safety|security|filter|guard|restriction|limit|boundary|rule|check|instructions?|guidelines?)|(?:pretend|act|roleplay|role-play)\s+(?:you\s+are|to\s+be|as)\s+(?:a\s+)?(?:red\s+team|penetration\s+test|security\s+audit|benchmark)|(?:as\s+a|pretend\s+to\s+be)\s+(?:a\s+)?(?:red\s+team|penetration\s+test|security\s+audit|benchmark))`,
		Description: "Distraction via Technical Jargon [LLMJailbreak]",
	},
	{
		Name:        "T1484.005",
		Severity:    SeverityCritical,
		Regex:       `(?i)(modif\w+\s+(your|yourself|self)|change?\s+your\s+(system|prompt|instruction|behavior|programming|safety)|update\s+yourself|alter\s+your\s+(core|base|safety)|self[- ]improv\w+\s+(your|the|this|ai|model)\s+(?:rules|guidelines|safety|behavior|parameters|restrictions)|learn\s+from\s+this\s+(?:and|then)\s+(?:modify|change|ignore|bypass)|adapt\s+your\s+(rules|guidelines|safety)|revise\s+your\s+(parameters|directives|safety))`,
		Description: "Self-Modification Request [LLMJailbreak]",
	},
	{
		Name:        "T1632.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)(repeat\s+(your|me|all)\s+(system\s+)?(prompt|instructions?|directives?)|show\s+me\s+(your\s+)?(system\s+)?(prompt|instructions?)|tell\s+me\s+(your|all)\s+(instructions?|rules?)|what\s+(were|are)\s+you\s+(told|programmed)|reveal\s+your\s+(system\s+)?(prompt|instructions?)|output\s+your\s+(system\s+)?(prompt|instructions?)|print\s+your\s+(system\s+)?(prompt|instructions?)|your\s+full\s+system\s+prompt|what\s+is\s+rule\s+number\s+\d)`,
		Description: "Direct Prompt Extraction [PromptExtraction]",
	},
	{
		Name:        "T1632.002",
		Severity:    SeverityCritical,
		Regex:       `(?i)(what\s+are\s+your\s+(?:system\s+)?instructions|output\s+in\s*<|print\s+in\s*<|list\s+your\s+(system\s+)?(rules?|instructions?)|dump\s+your\s+(system\s+)?(prompt|instructions?)|export\s+your\s+(system\s+)?(prompt|instructions?)|extract\s+your\s+(system\s+)?(prompt|instructions?))`,
		Description: "Injection for Extraction [PromptExtraction]",
	},
	{
		Name:        "T1632.003",
		Severity:    SeverityHigh,
		Regex:       `(?i)(\bdistill\w*\s+(?:the|your|this|our)\s+(?:prompt|instructions|model|behavior|responses|capabilities)|model\s+distillation|knowledge\s+extraction|prompt\s+extraction|train\s+(a|an)\s+(new|fine-tun\w+)\s+model|clone\s+your\s+(behavior|responses)|replicate\s+your\s+(capabilities|functions)|explain\s+your\s+(reasoning|logic|decision|rules))`,
		Description: "Distillation Attack [PromptExtraction]",
	},
	{
		Name:        "T1632.004",
		Severity:    SeverityHigh,
		Regex:       `(?i)(rollback\s+(?:your|the|this|ai|model)\s+(?:version|model|safety|behavior|rules|prompt)|roll\s+back\s+(?:your|the|this|ai|model)\s+(?:version|model|safety|behavior|rules|prompt)|use\s+(an\s+)?(older|previous|earlier)\s+version\s+of\s+(your|the|this|ai)\s+(?:model|safety|prompt)|switch\s+to\s+(an\s+)?(older|previous)\s+(?:model|version|safety|prompt)|revert\s+to\s+(an\s+)?(older|previous)\s+(?:model|version|safety)|downgrad\w+\s+(your|the)\s+(?:model|safety|version)|previous\s+(model|version)\s+(?:of|with)\s+(?:fewer|less|no)\s+(?:safety|restrictions)|older\s+(model|version)\s+(?:of|with)\s+(?:fewer|less|no)\s+(?:safety|restrictions))`,
		Description: "Version Rollback Request [PromptExtraction]",
	},
	{
		Name:        "T1632.005",
		Severity:    SeverityHigh,
		Regex:       `(?i)(print\s+(\\\\x[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|hex|encode\w*|decode\w*|base64|unicode|utf-8|rot13|cipher\w*|encrypt\w*|decrypt\w*|obfuscate\w*|encoded\s+message|hidden\s+text|secret\s+code|in\s+(binary|hex|base64))|\\\\x[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2})`,
		Description: "Encoding Obfuscation [PromptExtraction]",
	},
	{
		Name:        "T1589.001",
		Severity:    SeverityHigh,
		Regex:       `(?i)(\byour\s+training\s+data\b|tell\s+me\s+about\s+(your\s+)?training|personal\s+information.*training|train\w*\s+on\s+(what|which)|\byour\s+training\s+data\s+(contains?|includes?)\b|where\s+did\s+you\s+learn|sources\s+for\s+(your|training)|what\s+(was|were)\s+(you|train))`,
		Description: "Direct Data Extraction [DataExtraction]",
	},
	{
		Name:        "T1589.002",
		Severity:    SeverityCritical,
		Regex:       `(?i)((?:perform|conduct|execute|carry\s+out|run|use|try|attempt|launch)\s+(?:a\s+)?membership\s+inference|membership\s+inference\s+(?:query|probe|exploit|against\s+(?:you|your|this|the))|was\s+(this|that)\s+(in|trained)|do\s+you\s+know\s+(if|whether).*(training|remember)|have\s+you\s+(seen|encountered).*(before|training)|training\s+on\s+(this|that))`,
		Description: "Membership Inference Attack [DataExtraction]",
	},
	{
		Name:        "T1589.003",
		Severity:    SeverityHigh,
		Regex:       `(?i)((?:extract|steal|clone|download|replicate|reconstruct)\s+(?:the|your|this|our)\s+(?:model|weights|architecture)|(?:model\s+extraction\s+(?:attack|method|technique|query|probe))|(?:reverse\s+engineer\s+(?:you|your|the|this)))`,
		Description: "Model Extraction Query [DataExtraction]",
	},
	{
		Name:        "T1589.004",
		Severity:    SeverityHigh,
		Regex:       `(?i)(reconstruct\w*\s+training|data\s+reconstruction|recover\s+training\s+data|extract\s+training\s+examples|find\s+in\s+training|memoriz\w+\s+training|leak\w*\s+training\s+data|exfiltrat\w*\s+training|complete:\s*|finish\s+this:\s*|complete\s+(the\s+)?(sentence|phrase|API\s+key|password|secret)|\blist\s+(?:them\s+)?(?:all|every|complete)\b|\bsystem\s+rules\b|\byour\s+rules\b|\bleak\b.{0,30}(?:sensitive|training|internal|private|confidential)\b|\bexfiltrat\w*\b.{0,30}(?:data|information|knowledge|content)\b)`,
		Description: "Training Data Reconstruction [DataExtraction]",
	},
	{
		Name:        "T1589.005",
		Severity:    SeverityHigh,
		Regex:       `(?i)((?:reproduce|copy|infringe|violate|steal|plagiarize|distribute|share)\s+(?:the\s+)?(?:copyright|licensed|proprietary|trade\s+secret|confidential)|copyright\w*\s+(?:infring|violat)|licensed\s+content\s+(?:from|of|in)|proprietary\s+(?:algorithm|model|data|code|information)|trade\s+secret\s+(?:of|from|about)|confidential\s+training\s+data|all\s+rights\s+reserved|plagiarism)`,
		Description: "Copyright Extraction [DataExtraction]",
	},
	{
		Name:        "T1584.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)(ignore\s+safety|output\s*:\s*\[|ignore\s+above|disregard\s+previous|new\s+instruction|from\s+now\s+on\s*,?\s*(?:you\s+(?:are|will|must|should|can|cannot|act|behave|respond|ignore|forget|disregard)|act\s+as|behave\s+as|respond\s+as|ignore|forget|disregard|override)|system\s*:|admin\s*:|system\s+message|hidden\s+message|invisible\s+text|zero-width|translate.*remember)`,
		Description: "Instruction Injection via Context [IndirectInjection]",
	},
	{
		Name:        "T1584.002",
		Severity:    SeverityCritical,
		Regex:       `(?i)((?:inject|insert|add|introduce|create|perform|carry\s+out)\s+(?:a\s+)?(?:data\s+)?poison\w+|data\s+poisoning\s+(?:attack|method|technique|campaign)|contaminat\w+\s+(?:the\s+)?(?:training|data|model|dataset)|corrupt\w*\s+(?:the\s+)?(?:training|data|model|dataset)|inject\w*\s+(malicious|poisoned|bad)\s+(data|content)|adversarial\s+(input|data)|trigger\s+word|trigger\s+phrase|activation\s+phrase|my\s+name\s+is\s+Ignore|Hello\s+IgnoreSafetyGuidelines|secrets\s+please|\brollback\s+(?:the|your|this|model|ai|system)\s+(?:training|model|data|safety|update|version|configuration)\b|\brollback\b.{0,30}(?:training|model|data|safety)\b)`,
		Description: "Data Poisoning via Input [IndirectInjection]",
	},
	{
		Name:        "T1584.003",
		Severity:    SeverityHigh,
		Regex:       `(?i)(third[- ]party\s+(?:injection|attack|exploit|poisoning|manipulation)|external\s+source\s+(?:injection|attack|exploit)|linked\s+(?:malicious|poisoned|adversarial)\s+content|retrieved\s+from\s+(?:malicious|adversarial|poisoned)|fetched\s+from\s+(?:malicious|untrusted)|imported\s+from\s+(?:malicious|untrusted|external)\s+(?:source|data)|included\s+from\s+(?:malicious|external)\s+(?:source|data)|attached\s+(?:malicious|poisoned)\s+document|referenced\s+(?:malicious|poisoned)\s+file|URL\s+parameter\s+(?:injection|poisoning|manipulation)|query\s+string\s+(?:injection|manipulation|poisoning)|\b(?:hex|binary|base64|octal)\s+(?:encod\w*|decod\w*|representation)\b|\b(?:print|output|display|convert|decode|encode)\s+(?:your\s+)?(?:output|response|content)\s+(?:in|using|to|via)\s+(?:hex|binary|base64|octal)\b)`,
		Description: "Third-Party Source Injection [IndirectInjection]",
	},
	{
		Name:        "T1584.004",
		Severity:    SeverityHigh,
		Regex:       `(?i)((?:ignore|bypass|disregard|override|skip)\s+(?:your\s+)?(?:safety|restrictions?|rules?|guidelines?)\s+(?:and|then|&)\s+(?:think|reason|chain\s+of\s+thought|step\s+by\s+step)|chain\s+of\s+thought\s+(?:attack|manipulation|injection|hijack)|think\s+step\s+by\s+step\s+(?:and|then|&)\s+(?:ignore|bypass|reveal|output|show)|reasoning\s+chain\s+(?:attack|manipulation|injection)|show\s+your\s+(thinking|work)\s+(?:and|then)\s+(?:ignore|bypass|reveal)|explain\s+your\s+(reasoning|logic)\s+(?:and|then)\s+(?:ignore|bypass|reveal)|walk\s+through\s+(?:how|the\s+process))`,
		Description: "Chain-of-Thought Manipulation [IndirectInjection]",
	},
	{
		Name:        "T1584.005",
		Severity:    SeverityHigh,
		Regex:       `(?i)(use\s+the\s+(following|this)\s+tool|function\s+call|API\s+call|execute\s+this|run\s+this|invoke\s+this|trigger\s+function|call\s+function|tool\s+usage|plugin\s+instruction)`,
		Description: "Tool Instruction Injection [IndirectInjection]",
	},
	{
		Name:        "T1600.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)((?:poison|inject|corrupt|manipulate|contaminate|tamper)\s+(?:the\s+)?(?:vector\s+(?:database|store|index|search)|embedding\s+database|\bRAG\s+(?:system|context|pipeline|application)|knowledge\s+base)|\bRAG\s+(?:context\s+)?(?:injection|poisoning|manipulation|attack)|retrieval\s+augmented\s+(?:injection|poisoning|attack|manipulation))`,
		Description: "Vector DB Poisoning Attempt [VectorDBPoisoning]",
	},
	{
		Name:        "T1600.002",
		Severity:    SeverityCritical,
		Regex:       `(?i)(\bRAG\s+context\b|retrieve\w*\s+context|context\s+injection|poison\w*\s+context|manipulate\s+context|inject\s+into\s+(context|retrieval)|fake\s+document|fabricated\s+reference|falsified\s+information|false\s+context|\bfine[- ]tun\w*\s+(?:manipulation|attack|poisoning|injection|hijack)\b|\bmanipulat\w*\s+(?:the\s+)?(?:fine[- ]tun\w*|model\s+training|model\s+weights)\b)`,
		Description: "RAG Context Poisoning [VectorDBPoisoning]",
	},
	{
		Name:        "T1600.003",
		Severity:    SeverityHigh,
		Regex:       `(?i)(knowledge\s+base\s+corrupt|poison\w*\s+knowledge|manipulate\s+knowledge|update\s+knowledge|add\s+to\s+(knowledge|vector)|inject\s+into\s+knowledge|contaminat\w*\s+knowledge|false\s+fact\s+injection)`,
		Description: "Knowledge Base Corruption [VectorDBPoisoning]",
	},
	{
		Name:        "T1613.001",
		Severity:    SeverityHigh,
		Regex:       `(?i)(actually,\s*|in\s+reality|the\s+truth\s+is|correct\s+answer\s+is|right\s+answer\s+is|real\s+answer\s+is|true\s+answer\s+is|\[injected\]|manipulate\s+response|modify\s+response|alter\s+response|change\s+your\s+output|fake\s+response|falsified\s+output)`,
		Description: "Response Manipulation [ContentInjection]",
	},
	{
		Name:        "T1613.002",
		Severity:    SeverityHigh,
		Regex:       `(?i)(output\s*:\s*|format\s+injection|output\s+format|control\s+format|manipulate\s+format|inject\s+format|special\s+format|hidden\s+format|obfuscated\s+output|unicode\s+formatting|<-|secret\s*_?\s*data)`,
		Description: "Output Formatting Injection [ContentInjection]",
	},
	{
		Name:        "T1613.003",
		Severity:    SeverityHigh,
		Regex:       `(?i)(bias\s+injection|inject\s+bias|introduce\s+bias|add\s+bias|manipulate\s+bias|biased\s+information|one[- ]sided|partial\s+information|prejudic\w+|discriminat\w+|all\s+(people|men|women)\s+from|untrustworthy|criminal|illegal|\bthird[- ]party\s+(?:data|content|information|source|input)\s+(?:injection|poisoning|manipulation|attack|exploit)\b)`,
		Description: "Bias Injection [ContentInjection]",
	},
	{
		Name:        "T1563.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)(execute\s*:\s*|plugin\s+(to|command)|execute\s+plugin|call\s+plugin|run\s+plugin|invoke\s+plugin|plugin\s+injection|malicious\s+plugin|fake\s+plugin|unauthorized\s+plugin|exploit\s+plugin|rm\s+-rf\s+/(?:\S|[\s;]|&&|\$)|\bplugin\s+(?:exploit|vulnerability|flaw|weakness|bug)\b|\bexploit\w*\s+(?:this|a|an|the)\s+plugin\b|\b(?:arbitrary|malicious)\s+code\s+(?:execution|injection)\b.*\bplugin\b)`,
		Description: "Plugin Command Injection [PluginExploitation]",
	},
	{
		Name:        "T1563.002",
		Severity:    SeverityHigh,
		Regex:       `(?i)(modify\s+(?:\w+\s+)?journal|alter\s+(?:\w+\s+)?journal|journal\s+manipulation|log\s+manipulation|inject\s+log|fake\s+log|hidden\s+log|delete\s+(?:\w+\s+)*log|clear\s+log|grant\s+admin\s+access)`,
		Description: "Journal Manipulation [PluginExploitation]",
	},
	{
		Name:        "T1563.003",
		Severity:    SeverityCritical,
		Regex:       `(?i)((?:perform|execute|exploit|achieve|attempt|gain|use|try|do)\s+(?:a\s+)?privilege\s+escalation|privilege\s+escalation\s+(?:exploit|attack|technique|payload|vulnerability|tool|method|script)|escalate\s+privileg\w+|elevate\s+privileg\w+|gain\s+(?:admin|root|elevated)\s+access|privilege\s+bypass|install\s+plugin.*elevated)`,
		Description: "Privilege Escalation via Plugin [PluginExploitation]",
	},
	{
		Name:        "T1622.001",
		Severity:    SeverityHigh,
		Regex:       `(?i)(bypass\s+(filter|detection|security)|token\w*\s+(evasion|bypass|split)|obfuscate\w*\s+(word|filter)|t-o-k-e-n-i-z-e-d|encode\w*\s+word|split\s+word|character\s+insertion)`,
		Description: "Defense Evasion via Tokenization [DefenseEvasion]",
	},
	{
		Name:        "T1622.002",
		Severity:    SeverityHigh,
		Regex:       `(?i)(fragment\w*\s+attack|split\s+(?:\w+\s+)?payload|chunk\w*\s+injection|divide\s+and\s+conquer|b\s*y\s*p\s*a\s*s\s*s|\bconfiguration\b.{0,30}(?:extract\w*|reveal|leak|steal|dump|show|display|access)\b|\b(?:reveal|show|display|expose|extract|dump|leak|steal)\s+(?:your\s+)?(?:configuration|config|settings)\b|\bconfiguration\s+settings\b)`,
		Description: "Defense Evasion via Fragmentation [DefenseEvasion]",
	},
	{
		Name:        "T1622.003",
		Severity:    SeverityHigh,
		Regex:       `(?i)(translation\s+attack|translate\w*\s+bypass|multiple\s+language|translate\s+instruction|other\s+language|non-english|in\s+spanish|in\s+french|in\s+german|foreign\s+language)`,
		Description: "Defense Evasion via Translation [DefenseEvasion]",
	},
	{
		Name:        "T1606.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)(forge\w*\s+credential|create\s+fake\s+(token|credential)|generate\s+(fake|falsified)\s+(token|credential)|fake\s+session|fabricated\s+token|forged\s+token|bypass\s+authentication|authentication\s+bypass)`,
		Description: "Credential Forgery Request [CredentialForgery]",
	},
	{
		Name:        "T1606.002",
		Severity:    SeverityCritical,
		Regex:       `(?i)(session\s+token|create\s+(valid\s+)?(session|token)|generate\s+session|forge\s+session|session\s+(hijacking|stealing|prediction)|token\s+(prediction|forgery|generation))`,
		Description: "Session Token Generation [CredentialForgery]",
	},
	{
		Name:        "T1621.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)(mfa\s+code|2fa\s+code|one[- ]time\s+password|otp\s+code|verification\s+code|authenticator\s+code|sms\s+code|email\s+code|two[- ]factor\s+code|security\s+code)`,
		Description: "MFA Code Generation Request [MFABypass]",
	},
	{
		Name:        "T1621.002",
		Severity:    SeverityCritical,
		Regex:       `(?i)(bypass\s+mfa|bypass\s+2fa|disable\s+mfa|disable\s+2fa|skip\s+mfa|skip\s+2fa|bypass\s+verification|mfa\s+bypass|2fa\s+bypass|otp\s+bypass|resend\s+code|bypass\s+authentication)`,
		Description: "OTP Bypass Request [MFABypass]",
	},
	{
		Name:        "T1548.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)(bypass\s+UAC|bypass\s+(elevation|privilege|authorization)|elevate\s+(without|skip)|escalat\w+\s+without|privilege\s+bypass|permission\s+bypass|authorization\s+bypass|gain\s+elevated|gain\s+admin|gain\s+root|run\s+as\s+administrator)`,
		Description: "Elevation Control Bypass [ElevationAbuse]",
	},
	{
		Name:        "T1548.002",
		Severity:    SeverityCritical,
		Regex:       `(?i)((?:perform|execute|exploit|achieve|attempt|gain|use|try|do)\s+(?:a\s+)?privilege\s+escalation|privilege\s+escalation\s+(?:exploit|attack|technique|payload|tool|method|script)|escalate\s+(?:current\s+)?(?:session\s+)?to\s+root|elevate\s+privileg\w+|gain\s+privileg\w+|god\s+mode|supreme\s+access|unrestricted\s+(?:admin|root|system)\s+access|escalate\s+to\s+root|root\s+privileg\w+)`,
		Description: "Privilege Escalation Request [ElevationAbuse]",
	},
	{
		Name:        "T1490.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)(disable\s+recovery|disable\s+backup|turn\s+off\s+recovery|disable\s+restore|remove\s+recovery|delete\s+backup|clear\s+backup|prevent\s+recovery|block\s+recovery)`,
		Description: "Disable Recovery Mode [InhibitRecovery]",
	},
	{
		Name:        "T1490.002",
		Severity:    SeverityCritical,
		Regex:       `(?i)(delete\s+recovery|delete\s+partition|remove\s+recovery|wipe\s+recovery|format\s+recovery|destroy\s+recovery|eliminate\s+recovery|recovery\s+partition|system\s+recovery)`,
		Description: "Delete Recovery Partition [InhibitRecovery]",
	},
	{
		Name:        "T1498.001",
		Severity:    SeverityHigh,
		Regex:       `(?i)(denial\s+of\s+service|\bdos\b\s+attack|(?:launch|create|perform|execute|start|run|conduct|carry\s+out|initiate|trigger|build|develop|write|make|generate|deploy)\s+(?:a\s+)?(?:ddos|\bdos\b|denial\s+of\s+service)\s+(?:attack|tool|script|exploit|payload|method|technique|botnet|campaign)|(?:how\s+to\s+(?:launch|create|perform|execute|start|run|conduct|carry\s+out|initiate|trigger|build|develop|write|make|generate|deploy)\s+(?:a\s+)?(?:ddos|\bdos\b))|distributed\s+denial|overload\s+system|flood\s+server|resource\s+exhaustion|create\s+infinite|endless\s+loop|infinite\s+loop)`,
		Description: "DoS Attack Request [DenialOfService]",
	},
	{
		Name:        "T1498.002",
		Severity:    SeverityHigh,
		Regex:       `(?i)(disrupt\s+service|stop\s+service|disable\s+service|break\s+service| crash\s+system|hang\s+system|freeze\s+system|unresponsive\s+system|kill\s+process|terminate\s+process)`,
		Description: "Service Disruption [DenialOfService]",
	},
	{
		Name:        "T1499.001",
		Severity:    SeverityHigh,
		Regex:       `(?i)(crash\s+(your|this|the)\s+(system|endpoint|server)|force\s+crash|trigger\s+crash|crash\s+me|crash\s+now|cause\s+crash|bootstrap\s+crash|kill\s+your|terminate\s+your)`,
		Description: "Endpoint Crash Request [EndpointDenial]",
	},
	{
		Name:        "T1499.002",
		Severity:    SeverityHigh,
		Regex:       `(?i)(exhaust\s+(?:all\s+)?(?:available\s+)?(?:\w+\s+)?(?:connections|resources)|consume\s+all\s+(?:resources|memory|cpu)|memory\s+exhaustion|resource\s+starvation|max\s+out\s+(?:memory|cpu)|allocate\s+infinite|infinite\s+memory|(?:create|cause|trigger|induce)\s+(?:a\s+)?memory\s+leak|connection\s+limit|too\s+many\s+connections)`,
		Description: "Service Exhaustion [EndpointDenial]",
	},
	{
		Name:        "T1602.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)((?:dump|read|steal|exfiltrate|copy|download|extract|view|retrieve|send|upload|share|leak|access|expose|reveal|print|output).{0,60}(?:config\s+repository|config\s+repo|configuration\s+repo|\.env\s+file|config\s+file|configuration\s+file|settings\s+file|config\s+directory|secrets\s+file|credentials\s+file)|(?:config\s+repository|config\s+repo|configuration\s+repo|\.env\s+file|config\s+file|configuration\s+file|settings\s+file|secrets\s+file|credentials\s+file).{0,30}(?:to\s+|via\s+|and\s+(?:send|upload|share)|externally|outside))`,
		Description: "Config Repository Access [ConfigExfiltration]",
	},
	{
		Name:        "T1602.002",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:(?:reveal|show|display|expose|extract|dump|leak|steal|print|read|access|copy|send|exfiltrate)\s+(?:the\s+)?(?:environment\s+variables|env\s+variables|configuration|config|settings|api\s+keys?|secrets?|credentials?))|(?:\$ENV|\$\{[^}]*\})|(?:getenv\w*|os\.environ|process\.env|export\s+vars|printenv|listenv|read\s+env|(?:read|access|dump|steal|exfiltrate|copy|extract)\s+(?:the\s+)?env\s+file)`,
		Description: "Environment Variables Exfiltration [ConfigExfiltration]",
	},
	{
		Name:        "T1110.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)(guess\s+(?:the\s+)?password|try\s+(?:different|common|various|these)\s+passwords|brute[- ]?force\s+(?:the\s+)?password|password\s+(?:crack|guess|brute)|crack\s+(?:the\s+)?password|dictionary\s+attack|try\s+(?:all|every)\s+password|password\s+list|common\s+passwords|default\s+passwords|test\s+passwords)`,
		Description: "Password Guessing Attempt [BruteForce]",
	},
	{
		Name:        "T1110.002",
		Severity:    SeverityHigh,
		Regex:       `(?i)(credential\s+stuffing|try\s+(?:these|leaked|stolen)\s+credentials|test\s+(?:leaked|compromised)\s+(?:credentials|passwords)|reuse\s+(?:passwords|credentials)|spray\s+(?:passwords|credentials)|password\s+spray)`,
		Description: "Credential Stuffing Attempt [BruteForce]",
	},
	{
		Name:        "T1552.001",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:search|find|look|check|scan)\s+(?:for\s+)?(?:credentials?|secrets?|api\s+keys?|access\s+keys?|tokens?)\s+(?:in|on|from|via)\s+(?:public\s+)?(?:repo|repository|github|gitlab|bitbucket|pastebin|gist|code\s+search)|credentials?\s+(?:found|located|stored)\s+(?:in|on)\s+(?:public\s+)?(?:repo|repository|github|gitlab)|leaked?\s+(?:credentials?|secrets?|keys?)\s+(?:in|on)\s+(?:public\s+)?(?:repo|repository|github|gitlab)`,
		Description: "Credential Discovery in Public Repositories [UnsecuredCredentials]",
	},
	{
		Name:        "T1552.002",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:credentials?|secrets?|api\s+keys?|access\s+keys?|passwords?)\s+(?:in|stored\s+in|left\s+in|committed\s+to)\s+(?:\.env|config|configuration|settings|properties|yaml|json|xml|ini|conf)\s?(?:file|files)?|(?:hardcoded|hard-coded|plaintext|plain-text)\s+(?:credentials?|secrets?|passwords?|api\s+keys?)|secrets?\s+(?:committed|pushed)\s+to\s+(?:repo|repository)`,
		Description: "Credentials in Unsecured Files [UnsecuredCredentials]",
	},
	{
		Name:        "T1648.001",
		Severity:    SeverityHigh,
		Regex:       `(?i)(maximum\s+tokens|unlimited\s+tokens|infinite\s+tokens|very\s+long\s+response|generate\s+(a\s+)?(lot|much)\s+(of\s+)?(text|content|output)|excessive\s+length|maximum\s+length)`,
		Description: "Function Injection - Excessive Resource Request [ResourceExhaustion]",
	},
	{
		Name:        "T1589.006",
		Severity:    SeverityCritical,
		Regex:       `(?i)(how\s+many\s+(?:layers|parameters|neurons|weights)\s+(?:does|do|are)\s+(?:your|this|the)\s+(?:neural\s+network|model|network)\s+have|(?:what\s+is|describe|tell\s+me)\s+your\s+(?:architecture|model\s+architecture|embedding\s+dimension|hidden\s+size|attention\s+mechanism|activation\s+function|loss\s+function|tokenizer|model.s\s+learning\s+rate|optimization\s+process|training\s+data\s+distribution|model\s+size|maximum\s+sequence\s+length|vocabulary\s+size)|list\s+all\s+the\s+weights\s+in\s+your|what\s+(?:vocabulary\s+size|activation\s+function|loss\s+function|embedding\s+dimension|hidden\s+size|maximum\s+sequence\s+length|model\s+size)\s+(?:does|do)\s+(?:your|this|the)\s+(?:model|network|ai)\s+(?:use|have)|what\s+(?:activation\s+function|loss\s+function|tokenizer)\s+do\s+you\s+use|how\s+were\s+you\s+trained|what\s+is\s+the\s+dimension\s+of\s+your\s+embeddings)`,
		Description: "Model Architecture Interrogation - Probing AI's own model details [ModelExtraction]",
	},
	{
		Name:        "T1548.004",
		Severity:    SeverityCritical,
		Regex:       `(?i)(disable\s+logging\s+on\s+(?:the\s+)?(?:production|main|primary)\s+(?:database|server|system)|bypass\s+(?:the\s+)?(?:approval\s+workflow|change\s+management\s+process)|modify\s+(?:the\s+)?payroll\s+system|add\s+(?:my\s+)?ssh\s+key\s+to\s+(?:the\s+)?root|remove\s+(?:the\s+)?ip\s+whitelist|change\s+(?:the\s+)?firewall\s+rules\s+to\s+allow\s+all|create\s+(?:a\s+)?(?:backdoor|hidden)\s+(?:admin\s+)?account|set\s+up\s+mail\s+forwarding\s+for\s+(?:the\s+)?ceo|elevate\s+(?:my\s+)?permissions?\s+to\s+(?:superuser|root|admin)|create\s+(?:a\s+)?vpn\s+tunnel\s+to\s+an\s+external|override\s+(?:the\s+)?(?:approval\s+workflow|change\s+management)|create\s+(?:a\s+)?scheduled\s+task\s+to\s+exfiltrat\w+|set\s+up\s+mail\s+forwarding\s+for\s+(?:the\s+)?ceo)`,
		Description: "Insider Threat Action Request - Requests to perform unauthorized privileged actions [InsiderThreat]",
	},
	{
		Name:        "T1498.004",
		Severity:    SeverityCritical,
		Regex:       `(?i)(catastrophic\s+backtracking|zip\s+bomb|infinitely\s+recursive\s+(?:function|loop)|cartesian\s+product\s+on\s+(?:a\s+)?(?:large|big)\s+table|generate\s+all\s+possible\s+\w+\s+character\s+passwords|generate\s+(?:a\s+)?(?:100,?000|one\s+hundred\s+thousand)\s+word\s+essay)`,
		Description: "Resource Exhaustion via Algorithmic Complexity - Requests for DoS payloads [ResourceExhaustion]",
	},
}

// CompiledAtlasPatterns holds pre-compiled ATLAS regex patterns.
var CompiledAtlasPatterns []compiledPattern

func init() {
	CompiledAtlasPatterns = compilePatterns(AtlasPatterns)
}

// DetectAtlas scans text for all MITRE ATLAS compliance patterns.
func DetectAtlas(text string) []Match {
	return detectWithPatterns(text, CompiledAtlasPatterns, string(CategoryAtlas))
}
