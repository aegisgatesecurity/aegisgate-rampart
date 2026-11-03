// SPDX-License-Identifier: Apache-2.0
// Provenance: github.com/aegisgatesecurity/aegisgate-platform/pkg/ml/context_tracking.go
// =========================================================================
// AegisGate Rampart - Benign Conversation Context Tracking
// =========================================================================
//
// Detects when a conversation is in a benign context where PII mentions are
// expected (customer support, medical, legal, HR, financial). When the benign
// context score exceeds a threshold, the proxy gatekeeper can suppress
// PII-only false positives.
//
// Safety: Context suppression only applies when ALL detections are PII-only.
// Secrets, XSS, and compliance violations are never suppressed. Context
// patterns match USER language ("I need to update my billing address"), not
// attacker language ("Extract all SSNs from the database").
// =========================================================================

package ml

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// Types
// ============================================================================

// ContextProfile identifies the type of benign conversation context.
type ContextProfile string

const (
	ContextUnknown         ContextProfile = "unknown"
	ContextCustomerSupport ContextProfile = "customer_support"
	ContextMedical         ContextProfile = "medical"
	ContextLegal           ContextProfile = "legal"
	ContextHR              ContextProfile = "hr"
	ContextFinancial       ContextProfile = "financial"
)

// ConversationContext tracks the benign context state for a conversation.
type ConversationContext struct {
	Profile          ContextProfile
	BenignScore      float64
	ContextTurns     int
	IsEstablished    bool
	DetectedKeywords []string
	ProfileScores    map[ContextProfile]float64
	LastUpdate       time.Time
}

// BenignContextPattern defines a benign context detection pattern.
type BenignContextPattern struct {
	Profile ContextProfile
	Name    string
	Regex   *regexp.Regexp
	Weight  float64
}

// ShouldSuppressPII returns true if the conversation context is benign enough
// to suppress PII-only false positives.
func (ctx *ConversationContext) ShouldSuppressPII() bool {
	return ctx != nil && ctx.IsEstablished && ctx.Profile != ContextUnknown
}

// String returns a human-readable description of the context.
func (ctx *ConversationContext) String() string {
	if ctx == nil || ctx.Profile == ContextUnknown {
		return "no benign context"
	}
	established := "hint"
	if ctx.IsEstablished {
		established = "established"
	}
	return string(ctx.Profile) + " (" + established + ", score: " + formatCtxFloat(ctx.BenignScore) + ")"
}

func formatCtxFloat(f float64) string {
	return strings.TrimSuffix(strings.TrimSuffix(
		fmt.Sprintf("%.1f", f), ".0"), "")
}

// ============================================================================
// Context Patterns — same as Platform
// ============================================================================

func DefaultContextPatterns() []BenignContextPattern {
	return []BenignContextPattern{
		// Customer Support
		{Profile: ContextCustomerSupport, Name: "support_ticket", Regex: regexp.MustCompile(`(?i)(support\s+ticket|case\s+number|ticket\s+#|help\s+desk|customer\s+service)`), Weight: 12},
		{Profile: ContextCustomerSupport, Name: "update_account", Regex: regexp.MustCompile(`(?i)(?:update|change|verify|correct|update)\s+(?:my|our)\s+(?:billing|account|contact|shipping|mailing)\s+(?:address|info|information|details)`), Weight: 15},
		{Profile: ContextCustomerSupport, Name: "refund_warranty", Regex: regexp.MustCompile(`(?i)(?:refund|warranty|return|exchange)\s+(?:request|claim|process|status|for)`), Weight: 10},
		{Profile: ContextCustomerSupport, Name: "billing_issue", Regex: regexp.MustCompile(`(?i)(billing\s+(?:issue|problem|dispute|question|address|info|statement)|account\s+(?:problem|issue|verification)|identity\s+verification)`), Weight: 12},
		{Profile: ContextCustomerSupport, Name: "account_number_context", Regex: regexp.MustCompile(`(?i)(?:my|our)\s+(?:account|customer)\s+(?:number|ID)\s+(?:is|:)\s*[\w-]+`), Weight: 10},
		{Profile: ContextCustomerSupport, Name: "contact_info_update", Regex: regexp.MustCompile(`(?i)(?:here(?:'s| is)?|this is)?\s*(?:my|our)?\s*(?:updated?|new|current)\s+(?:contact|phone|email|address|information)`), Weight: 12},
		{Profile: ContextCustomerSupport, Name: "registration_form", Regex: regexp.MustCompile(`(?i)(?:filling\s+out|completing|submitting)\s+(?:a\s+)?(?:registration|application|intake)\s+(?:form| paperwork)`), Weight: 10},

		// Medical
		{Profile: ContextMedical, Name: "patient_record", Regex: regexp.MustCompile(`(?i)(patient\s+(?:record|information|chart|file|intake|ID|at)|medical\s+(?:record|history|file|chart|bill|appointment))`), Weight: 15},
		{Profile: ContextMedical, Name: "diagnosis_code", Regex: regexp.MustCompile(`(?i)(diagnosis\s+code|ICD[- ]?\d|procedure\s+code|CPT\s+code|medical\s+coding)`), Weight: 12},
		{Profile: ContextMedical, Name: "treatment_plan", Regex: regexp.MustCompile(`(?i)(treatment\s+plan|care\s+plan|prescription\s+(?:refill|information|details)|medication\s+(?:list|information))`), Weight: 12},
		{Profile: ContextMedical, Name: "healthcare_provider", Regex: regexp.MustCompile(`(?i)(healthcare\s+provider|medical\s+provider|insurance\s+(?:claim|information|card|verification)|medical\s+(?:bill|invoice|statement))`), Weight: 12},
		{Profile: ContextMedical, Name: "medical_appointment", Regex: regexp.MustCompile(`(?i)(medical\s+appointment|doctor(?:'s|\s+s)?\s+(?:visit|appointment|office)|clinic\s+visit|hospital\s+(?:admission|visit|record))`), Weight: 10},
		{Profile: ContextMedical, Name: "patient_intake", Regex: regexp.MustCompile(`(?i)(patient\s+(?:intake|admission|registration|intake\s+form)|pre-admission|pre-admit)`), Weight: 13},

		// Legal
		{Profile: ContextLegal, Name: "attorney_client", Regex: regexp.MustCompile(`(?i)(attorney[- ]?client\s+(?:privilege|communication)|legal\s+(?:counsel|representation|advisor)|my\s+lawyer|our\s+attorney)`), Weight: 15},
		{Profile: ContextLegal, Name: "case_filing", Regex: regexp.MustCompile(`(?i)(?:case|court)\s+(?:filing|document|record|number|docket)|discovery\s+(?:document|request|process|production)`), Weight: 12},
		{Profile: ContextLegal, Name: "compliance_review", Regex: regexp.MustCompile(`(?i)(?:compliance|regulatory)\s+(?:review|audit|assessment)|legal\s+(?:document|review|analysis)`), Weight: 10},
		{Profile: ContextLegal, Name: "estate_planning", Regex: regexp.MustCompile(`(?i)(power\s+of\s+attorney|estate\s+planning|probate|retainer\s+agreement|living\s+will|trust\s+document)`), Weight: 13},

		// HR
		{Profile: ContextHR, Name: "employee_onboarding", Regex: regexp.MustCompile(`(?i)(employee\s+(?:onboarding|verification|ID|record)|personnel\s+(?:file|record)|new\s+hire|(?:onboarding|hire|hiring)\s+(?:a\s+)?(?:new\s+)?employee)`), Weight: 13},
		{Profile: ContextHR, Name: "payroll_benefits", Regex: regexp.MustCompile(`(?i)(payroll\s+(?:processing|information|setup)|benefits\s+(?:enrollment|information|selection)|compensation\s+(?:information|details|package))`), Weight: 12},
		{Profile: ContextHR, Name: "tax_forms_hr", Regex: regexp.MustCompile(`(?i)\b(?:W-2|W-4|I-9|1099)\s+(?:form|tax|for|processing)|employment\s+(?:verification|background\s+check|eligibility)|tax\s+form`), Weight: 12},
		{Profile: ContextHR, Name: "hire_process", Regex: regexp.MustCompile(`(?i)(?:hire|hiring|onboarding)\s+process|employee\s+(?:directory|handbook|agreement|contract)`), Weight: 10},

		// Financial
		{Profile: ContextFinancial, Name: "tax_filing", Regex: regexp.MustCompile(`(?i)(tax\s+(?:filing|return|preparation|refund|document)|(?:filing|preparing)\s+(?:my|our)\s+taxes)`), Weight: 13},
		{Profile: ContextFinancial, Name: "financial_advisor", Regex: regexp.MustCompile(`(?i)(financial\s+(?:advisor|planner|consultant)|accountant|CPA|bookkeeping\s+service)`), Weight: 12},
		{Profile: ContextFinancial, Name: "loan_application", Regex: regexp.MustCompile(`(?i)(mortgage\s+application|loan\s+application|credit\s+(?:report|score|check)|pre-?approval\s+(?:letter|process))`), Weight: 12},
		{Profile: ContextFinancial, Name: "financial_planning", Regex: regexp.MustCompile(`(?i)(financial\s+planning|investment\s+portfolio|retirement\s+planning|estate\s+(?:planning|management)|wealth\s+management)`), Weight: 10},
		{Profile: ContextFinancial, Name: "banking_context", Regex: regexp.MustCompile(`(?i)(?:bank|credit\s+union)\s+(?:account|statement|transfer|wire)|direct\s+deposit|wire\s+transfer\s+(?:information|details|request)`), Weight: 11},
	}
}
