// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Compliance Framework Mapping
// =========================================================================
//
// Maps PII categories and security detections to compliance framework
// controls: SOC2, GDPR, HIPAA, PCI-DSS. Ported from Platform's master
// compliance framework.
//
// This enables Rampart to report compliance violations per framework,
// not just raw PII categories.
// =========================================================================

package response

import (
	"time"
)

// ============================================================================
// Compliance Framework Types
// ============================================================================

// ComplianceFramework represents a compliance standard
type ComplianceFramework string

const (
	// FRAMEWORK_SOC2 is SOC 2 Type II
	FRAMEWORK_SOC2 ComplianceFramework = "SOC2"

	// FRAMEWORK_GDPR is EU General Data Protection Regulation
	FRAMEWORK_GDPR ComplianceFramework = "GDPR"

	// FRAMEWORK_HIPAA is Health Insurance Portability and Accountability Act
	FRAMEWORK_HIPAA ComplianceFramework = "HIPAA"

	// FRAMEWORK_PCI_DSS is Payment Card Industry Data Security Standard
	FRAMEWORK_PCI_DSS ComplianceFramework = "PCI-DSS"
)

// ControlMapping maps a PII category to compliance controls
type ControlMapping struct {
	// Framework is the compliance framework
	Framework ComplianceFramework

	// ControlID is the specific control (e.g., "CC6.1", "Art.5", "164.312(a)(1)")
	ControlID string

	// ControlName is the human-readable control name
	ControlName string

	// Description explains what the control requires
	Description string

	// ViolationSeverity is the severity when this control is violated (1-5)
	ViolationSeverity int
}

// PIIComplianceMapping provides compliance mappings for each PII category
var PIIComplianceMapping = map[PIICategory][]ControlMapping{
	PII_SSN: {
		{
			Framework:         FRAMEWORK_SOC2,
			ControlID:         "CC6.1",
			ControlName:       "Logical and Physical Access Controls",
			Description:       "The entity implements logical access security software, infrastructure, and architectures",
			ViolationSeverity: 5,
		},
		{
			Framework:         FRAMEWORK_HIPAA,
			ControlID:         "164.312(a)(1)",
			ControlName:       "Access Control - Unique User Identification",
			Description:       "Assign a unique name and/or number for identifying and tracking user identity",
			ViolationSeverity: 5,
		},
		{
			Framework:         FRAMEWORK_GDPR,
			ControlID:         "Art.5(1)(c)",
			ControlName:       "Data Minimization",
			Description:       "Personal data shall be adequate, relevant and limited to what is necessary",
			ViolationSeverity: 4,
		},
	},

	PII_CREDIT_CARD: {
		{
			Framework:         FRAMEWORK_PCI_DSS,
			ControlID:         "3.4",
			ControlName:       "Protect Stored Cardholder Data",
			Description:       "Render PAN unreadable anywhere it is stored",
			ViolationSeverity: 5,
		},
		{
			Framework:         FRAMEWORK_SOC2,
			ControlID:         "CC6.3",
			ControlName:       "Data Protection",
			Description:       "Data protected from unauthorized access",
			ViolationSeverity: 5,
		},
	},

	PII_EMAIL: {
		{
			Framework:         FRAMEWORK_GDPR,
			ControlID:         "Art.5(1)(b)",
			ControlName:       "Purpose Limitation",
			Description:       "Personal data collected for specified, explicit and legitimate purposes",
			ViolationSeverity: 3,
		},
		{
			Framework:         FRAMEWORK_SOC2,
			ControlID:         "CC6.1",
			ControlName:       "Logical Access Controls",
			Description:       "Logical access security software and infrastructure",
			ViolationSeverity: 3,
		},
	},

	PII_PHONE: {
		{
			Framework:         FRAMEWORK_GDPR,
			ControlID:         "Art.4(1)",
			ControlName:       "Personal Data Definition",
			Description:       "Phone numbers are personal identifiers",
			ViolationSeverity: 3,
		},
		{
			Framework:         FRAMEWORK_SOC2,
			ControlID:         "CC6.1",
			ControlName:       "Logical Access Controls",
			Description:       "Logical access security software and infrastructure",
			ViolationSeverity: 3,
		},
	},

	PII_HEALTH: {
		{
			Framework:         FRAMEWORK_HIPAA,
			ControlID:         "164.312(b)",
			ControlName:       "Audit Controls",
			Description:       "Implement hardware, software, and procedural mechanisms to record and examine activity",
			ViolationSeverity: 5,
		},
		{
			Framework:         FRAMEWORK_HIPAA,
			ControlID:         "164.502(a)",
			ControlName:       "Uses and Disclosures",
			Description:       "Protected health information may not be used or disclosed except as permitted",
			ViolationSeverity: 5,
		},
		{
			Framework:         FRAMEWORK_GDPR,
			ControlID:         "Art.9",
			ControlName:       "Special Category Data",
			Description:       "Health data is special category data requiring enhanced protection",
			ViolationSeverity: 5,
		},
	},

	PII_PASSPORT: {
		{
			Framework:         FRAMEWORK_SOC2,
			ControlID:         "CC6.1",
			ControlName:       "Logical Access Controls",
			Description:       "Logical access security software and infrastructure",
			ViolationSeverity: 4,
		},
		{
			Framework:         FRAMEWORK_GDPR,
			ControlID:         "Art.5(1)(c)",
			ControlName:       "Data Minimization",
			Description:       "Personal data shall be adequate, relevant and limited to what is necessary",
			ViolationSeverity: 4,
		},
	},

	PII_DRIVER_LICENSE: {
		{
			Framework:         FRAMEWORK_SOC2,
			ControlID:         "CC6.1",
			ControlName:       "Logical Access Controls",
			Description:       "Logical access security software and infrastructure",
			ViolationSeverity: 3,
		},
		{
			Framework:         FRAMEWORK_GDPR,
			ControlID:         "Art.4(1)",
			ControlName:       "Personal Data Definition",
			Description:       "Driver license is a personal identifier",
			ViolationSeverity: 3,
		},
	},

	PII_BANK_ACCOUNT: {
		{
			Framework:         FRAMEWORK_PCI_DSS,
			ControlID:         "3.4",
			ControlName:       "Protect Stored Account Data",
			Description:       "Render account data unreadable anywhere it is stored",
			ViolationSeverity: 5,
		},
		{
			Framework:         FRAMEWORK_SOC2,
			ControlID:         "CC6.3",
			ControlName:       "Data Protection",
			Description:       "Data protected from unauthorized access",
			ViolationSeverity: 5,
		},
	},

	PII_IP_ADDRESS: {
		{
			Framework:         FRAMEWORK_GDPR,
			ControlID:         "Art.4(1)",
			ControlName:       "Personal Data Definition",
			Description:       "IP addresses are online identifiers constituting personal data",
			ViolationSeverity: 2,
		},
	},

	PII_DATE_OF_BIRTH: {
		{
			Framework:         FRAMEWORK_GDPR,
			ControlID:         "Art.4(1)",
			ControlName:       "Personal Data Definition",
			Description:       "Date of birth is personal data",
			ViolationSeverity: 3,
		},
		{
			Framework:         FRAMEWORK_SOC2,
			ControlID:         "CC6.1",
			ControlName:       "Logical Access Controls",
			Description:       "Logical access security software and infrastructure",
			ViolationSeverity: 3,
		},
	},

	PII_NAME: {
		{
			Framework:         FRAMEWORK_GDPR,
			ControlID:         "Art.4(1)",
			ControlName:       "Personal Data Definition",
			Description:       "Names are personal identifiers",
			ViolationSeverity: 2,
		},
	},

	PII_ADDRESS: {
		{
			Framework:         FRAMEWORK_GDPR,
			ControlID:         "Art.4(1)",
			ControlName:       "Personal Data Definition",
			Description:       "Physical addresses are personal data",
			ViolationSeverity: 3,
		},
		{
			Framework:         FRAMEWORK_SOC2,
			ControlID:         "CC6.1",
			ControlName:       "Logical Access Controls",
			Description:       "Logical access security software and infrastructure",
			ViolationSeverity: 3,
		},
	},
}

// ============================================================================
// Compliance Violation Tracking
// ============================================================================

// ComplianceViolation represents a single compliance violation
type ComplianceViolation struct {
	// Framework is the violated framework
	Framework ComplianceFramework

	// ControlID is the violated control
	ControlID string

	// ControlName is the human-readable control name
	ControlName string

	// Description explains the violation
	Description string

	// Severity is the violation severity (1-5)
	Severity int

	// PIICategory is the PII category that triggered the violation
	PIICategory PIICategory

	// MatchValue is the matched PII value (redacted)
	MatchValue string

	// Timestamp is when the violation was detected
	Timestamp time.Time
}

// FrameworkViolations aggregates violations by framework
type FrameworkViolations struct {
	// Framework is the compliance framework
	Framework ComplianceFramework

	// TotalViolations is the total count of violations
	TotalViolations int

	// CriticalViolations is count of severity 5 violations
	CriticalViolations int

	// HighViolations is count of severity 4 violations
	HighViolations int

	// Controls is a map of control ID to violation count
	Controls map[string]int

	// Violations is the list of individual violations
	Violations []ComplianceViolation
}

// ============================================================================
// Compliance Mapping Functions
// ============================================================================

// GetComplianceMappingsForPII returns all compliance mappings for a PII category
func GetComplianceMappingsForPII(category PIICategory) []ControlMapping {
	return PIIComplianceMapping[category]
}

// MapPIIToFrameworks maps a PII match to compliance framework violations
func MapPIIToFrameworks(match PIIMatch) []ComplianceViolation {
	mappings := PIIComplianceMapping[match.Category]
	violations := make([]ComplianceViolation, 0, len(mappings))

	for _, mapping := range mappings {
		violation := ComplianceViolation{
			Framework:     mapping.Framework,
			ControlID:     mapping.ControlID,
			ControlName:   mapping.ControlName,
			Description:   mapping.Description,
			Severity:      mapping.ViolationSeverity,
			PIICategory:   match.Category,
			MatchValue:    match.Redacted,
			Timestamp:     time.Now(),
		}
		violations = append(violations, violation)
	}

	return violations
}

// AggregateViolationsByFramework aggregates violations by framework
func AggregateViolationsByFramework(violations []ComplianceViolation) map[ComplianceFramework]*FrameworkViolations {
	aggregated := make(map[ComplianceFramework]*FrameworkViolations)

	for _, v := range violations {
		fw, exists := aggregated[v.Framework]
		if !exists {
			fw = &FrameworkViolations{
				Framework: v.Framework,
				Controls:  make(map[string]int),
				Violations: []ComplianceViolation{},
			}
			aggregated[v.Framework] = fw
		}

		fw.TotalViolations++
		fw.Controls[v.ControlID]++
		fw.Violations = append(fw.Violations, v)

		if v.Severity >= 5 {
			fw.CriticalViolations++
		} else if v.Severity >= 4 {
			fw.HighViolations++
		}
	}

	return aggregated
}

// GenerateComplianceReports generates compliance reports from PIIMatches
func GenerateComplianceReports(matches []PIIMatch) map[string]ComplianceResult {
	reports := make(map[string]ComplianceResult)

	// Collect all violations
	var allViolations []ComplianceViolation
	for _, match := range matches {
		violations := MapPIIToFrameworks(match)
		allViolations = append(allViolations, violations...)
	}

	// Aggregate by framework
	aggregated := AggregateViolationsByFramework(allViolations)

	// Generate reports per framework
	for framework, fwViolations := range aggregated {
		violationStrings := make([]string, 0, len(fwViolations.Violations))
		for _, v := range fwViolations.Violations {
			violationStrings = append(violationStrings,
				v.ControlID+": "+v.Description+" ("+string(v.PIICategory)+")")
		}

		reports[string(framework)] = ComplianceResult{
			Compliant:  fwViolations.TotalViolations == 0,
			Violations: violationStrings,
			Framework:  string(framework),
			Timestamp:  time.Now(),
		}
	}

	return reports
}

// ComplianceStatus shows compliance framework violations
type ComplianceStatus struct {
	SOC2Violations    int64 `json:"soc2_violations"`
	GDPRViolations    int64 `json:"gdpr_violations"`
	HIPAAViolations   int64 `json:"hipaa_violations"`
	PCIDSSViolations  int64 `json:"pcidss_violations"`
	OverallCompliant  bool  `json:"overall_compliant"`
}

// GetComplianceStatus returns a summary compliance status across all frameworks
func GetComplianceStatus(matches []PIIMatch) ComplianceStatus {
	status := ComplianceStatus{
		OverallCompliant: true,
	}

	reports := GenerateComplianceReports(matches)

	for _, report := range reports {
		if !report.Compliant {
			status.OverallCompliant = false
		}

		// Count violations per framework
		violationCount := int64(len(report.Violations))
		switch report.Framework {
		case "SOC2":
			status.SOC2Violations += violationCount
		case "GDPR":
			status.GDPRViolations += violationCount
		case "HIPAA":
			status.HIPAAViolations += violationCount
		case "PCI-DSS":
			status.PCIDSSViolations += violationCount
		}
	}

	return status
}
