// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Compliance Framework Mapping Tests
// =========================================================================

package response

import (
	"testing"
	"time"
)

func TestGetComplianceMappingsForPII(t *testing.T) {
	tests := []struct {
		name        string
		category    PIICategory
		expectCount int
		expectSOC2  bool
		expectGDPR  bool
		expectHIPAA bool
		expectPCI   bool
	}{
		{
			name:        "SSN maps to SOC2, HIPAA, GDPR",
			category:    PII_SSN,
			expectCount: 3,
			expectSOC2:  true,
			expectHIPAA: true,
			expectGDPR:  true,
		},
		{
			name:        "Credit Card maps to PCI-DSS, SOC2",
			category:    PII_CREDIT_CARD,
			expectCount: 2,
			expectPCI:   true,
			expectSOC2:  true,
		},
		{
			name:        "Health Info maps to HIPAA, GDPR",
			category:    PII_HEALTH,
			expectCount: 3,
			expectHIPAA: true,
			expectGDPR:  true,
		},
		{
			name:        "Email maps to GDPR, SOC2",
			category:    PII_EMAIL,
			expectCount: 2,
			expectGDPR:  true,
			expectSOC2:  true,
		},
		{
			name:        "IP Address maps to GDPR only",
			category:    PII_IP_ADDRESS,
			expectCount: 1,
			expectGDPR:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappings := GetComplianceMappingsForPII(tt.category)

			if len(mappings) != tt.expectCount {
				t.Errorf("Expected %d mappings, got %d", tt.expectCount, len(mappings))
			}

			hasSOC2 := false
			hasGDPR := false
			hasHIPAA := false
			hasPCI := false

			for _, m := range mappings {
				switch m.Framework {
				case FRAMEWORK_SOC2:
					hasSOC2 = true
				case FRAMEWORK_GDPR:
					hasGDPR = true
				case FRAMEWORK_HIPAA:
					hasHIPAA = true
				case FRAMEWORK_PCI_DSS:
					hasPCI = true
				}
			}

			if tt.expectSOC2 && !hasSOC2 {
				t.Error("Expected SOC2 mapping")
			}
			if tt.expectGDPR && !hasGDPR {
				t.Error("Expected GDPR mapping")
			}
			if tt.expectHIPAA && !hasHIPAA {
				t.Error("Expected HIPAA mapping")
			}
			if tt.expectPCI && !hasPCI {
				t.Error("Expected PCI-DSS mapping")
			}
		})
	}
}

func TestMapPIIToFrameworks(t *testing.T) {
	match := PIIMatch{
		Category: PII_SSN,
		Start:    0,
		End:      11,
		Value:    "123-45-6789",
		Severity: 5,
		Redacted: "XXX-XX-6789",
	}

	violations := MapPIIToFrameworks(match)

	if len(violations) != 3 {
		t.Errorf("Expected 3 violations for SSN, got %d", len(violations))
	}

	for _, v := range violations {
		if v.PIICategory != PII_SSN {
			t.Errorf("Expected PIICategory to be SSN, got %s", v.PIICategory)
		}
		if v.MatchValue != "XXX-XX-6789" {
			t.Errorf("Expected redacted value, got %s", v.MatchValue)
		}
		if v.Timestamp.IsZero() {
			t.Error("Expected timestamp to be set")
		}
	}
}

func TestAggregateViolationsByFramework(t *testing.T) {
	violations := []ComplianceViolation{
		{
			Framework:   FRAMEWORK_SOC2,
			ControlID:   "CC6.1",
			Severity:    5,
			PIICategory: PII_SSN,
		},
		{
			Framework:   FRAMEWORK_SOC2,
			ControlID:   "CC6.3",
			Severity:    4,
			PIICategory: PII_CREDIT_CARD,
		},
		{
			Framework:   FRAMEWORK_HIPAA,
			ControlID:   "164.312(a)(1)",
			Severity:    5,
			PIICategory: PII_HEALTH,
		},
		{
			Framework:   FRAMEWORK_GDPR,
			ControlID:   "Art.5(1)(c)",
			Severity:    3,
			PIICategory: PII_SSN,
		},
	}

	aggregated := AggregateViolationsByFramework(violations)

	if len(aggregated) != 3 {
		t.Errorf("Expected 3 frameworks, got %d", len(aggregated))
	}

	soc2 := aggregated[FRAMEWORK_SOC2]
	if soc2.TotalViolations != 2 {
		t.Errorf("Expected SOC2 to have 2 violations, got %d", soc2.TotalViolations)
	}
	if soc2.CriticalViolations != 1 {
		t.Errorf("Expected SOC2 to have 1 critical violation, got %d", soc2.CriticalViolations)
	}
	if soc2.HighViolations != 1 {
		t.Errorf("Expected SOC2 to have 1 high violation, got %d", soc2.HighViolations)
	}

	hipaa := aggregated[FRAMEWORK_HIPAA]
	if hipaa.TotalViolations != 1 {
		t.Errorf("Expected HIPAA to have 1 violation, got %d", hipaa.TotalViolations)
	}
	if hipaa.CriticalViolations != 1 {
		t.Errorf("Expected HIPAA to have 1 critical violation, got %d", hipaa.CriticalViolations)
	}
}

func TestGenerateComplianceReports(t *testing.T) {
	matches := []PIIMatch{
		{
			Category: PII_SSN,
			Value:    "123-45-6789",
			Redacted: "XXX-XX-6789",
			Severity: 5,
		},
		{
			Category: PII_CREDIT_CARD,
			Value:    "4111111111111111",
			Redacted: "****-****-****-1111",
			Severity: 5,
		},
	}

	reports := GenerateComplianceReports(matches)

	// Should have reports for SOC2, HIPAA, GDPR, PCI-DSS
	if len(reports) == 0 {
		t.Fatal("Expected compliance reports, got none")
	}

	// Check SOC2 report
	soc2Report, exists := reports["SOC2"]
	if !exists {
		t.Fatal("Expected SOC2 report")
	}
	if soc2Report.Compliant {
		t.Error("Expected SOC2 to be non-compliant")
	}
	if len(soc2Report.Violations) == 0 {
		t.Error("Expected SOC2 violations")
	}

	// Check PCI-DSS report
	pciReport, exists := reports["PCI-DSS"]
	if !exists {
		t.Fatal("Expected PCI-DSS report")
	}
	if pciReport.Compliant {
		t.Error("Expected PCI-DSS to be non-compliant")
	}
}

func TestGenerateComplianceReports_NoPII(t *testing.T) {
	matches := []PIIMatch{}
	reports := GenerateComplianceReports(matches)

	if len(reports) != 0 {
		t.Errorf("Expected no reports for empty matches, got %d", len(reports))
	}
}

func TestGetComplianceStatus(t *testing.T) {
	tests := []struct {
		name            string
		matches         []PIIMatch
		expectCompliant bool
		expectSOC2      int64
		expectHIPAA     int64
		expectPCI       int64
		expectGDPR      int64
	}{
		{
			name:            "No PII = compliant",
			matches:         []PIIMatch{},
			expectCompliant: true,
			expectSOC2:      0,
			expectHIPAA:     0,
			expectPCI:       0,
			expectGDPR:      0,
		},
		{
			name: "SSN = non-compliant with multiple violations",
			matches: []PIIMatch{
				{
					Category: PII_SSN,
					Value:    "123-45-6789",
					Redacted: "XXX-XX-6789",
					Severity: 5,
				},
			},
			expectCompliant: false,
			expectSOC2:      1,
			expectHIPAA:     1,
			expectGDPR:      1,
		},
		{
			name: "Credit card = PCI-DSS violation",
			matches: []PIIMatch{
				{
					Category: PII_CREDIT_CARD,
					Value:    "4111111111111111",
					Redacted: "****-****-****-1111",
					Severity: 5,
				},
			},
			expectCompliant: false,
			expectPCI:       1,
			expectSOC2:      1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := GetComplianceStatus(tt.matches)

			if status.OverallCompliant != tt.expectCompliant {
				t.Errorf("Expected OverallCompliant=%v, got %v", tt.expectCompliant, status.OverallCompliant)
			}
			if status.SOC2Violations != tt.expectSOC2 {
				t.Errorf("Expected SOC2Violations=%d, got %d", tt.expectSOC2, status.SOC2Violations)
			}
			if status.HIPAAViolations != tt.expectHIPAA {
				t.Errorf("Expected HIPAAViolations=%d, got %d", tt.expectHIPAA, status.HIPAAViolations)
			}
			if status.PCIDSSViolations != tt.expectPCI {
				t.Errorf("Expected PCIDSSViolations=%d, got %d", tt.expectPCI, status.PCIDSSViolations)
			}
			if status.GDPRViolations != tt.expectGDPR {
				t.Errorf("Expected GDPRViolations=%d, got %d", tt.expectGDPR, status.GDPRViolations)
			}
		})
	}
}

func TestComplianceViolation_Structure(t *testing.T) {
	violation := ComplianceViolation{
		Framework:   FRAMEWORK_SOC2,
		ControlID:   "CC6.1",
		ControlName: "Logical Access Controls",
		Description: "Test violation",
		Severity:    5,
		PIICategory: PII_SSN,
		MatchValue:  "XXX-XX-6789",
		Timestamp:   time.Now(),
	}

	if violation.Framework != FRAMEWORK_SOC2 {
		t.Errorf("Expected Framework SOC2, got %s", violation.Framework)
	}
	if violation.ControlID != "CC6.1" {
		t.Errorf("Expected ControlID CC6.1, got %s", violation.ControlID)
	}
	if violation.Severity != 5 {
		t.Errorf("Expected Severity 5, got %d", violation.Severity)
	}
}

func TestFrameworkViolations_Aggregation(t *testing.T) {
	fw := &FrameworkViolations{
		Framework:  FRAMEWORK_SOC2,
		Controls:   make(map[string]int),
		Violations: []ComplianceViolation{},
	}

	// Add violations
	fw.TotalViolations = 5
	fw.CriticalViolations = 2
	fw.HighViolations = 2
	fw.Controls["CC6.1"] = 3
	fw.Controls["CC6.3"] = 2

	if fw.TotalViolations != 5 {
		t.Errorf("Expected 5 total violations, got %d", fw.TotalViolations)
	}
	if fw.CriticalViolations != 2 {
		t.Errorf("Expected 2 critical violations, got %d", fw.CriticalViolations)
	}
	if len(fw.Controls) != 2 {
		t.Errorf("Expected 2 controls, got %d", len(fw.Controls))
	}
}

func TestComplianceFramework_Constants(t *testing.T) {
	if FRAMEWORK_SOC2 != "SOC2" {
		t.Errorf("Expected SOC2, got %s", FRAMEWORK_SOC2)
	}
	if FRAMEWORK_GDPR != "GDPR" {
		t.Errorf("Expected GDPR, got %s", FRAMEWORK_GDPR)
	}
	if FRAMEWORK_HIPAA != "HIPAA" {
		t.Errorf("Expected HIPAA, got %s", FRAMEWORK_HIPAA)
	}
	if FRAMEWORK_PCI_DSS != "PCI-DSS" {
		t.Errorf("Expected PCI-DSS, got %s", FRAMEWORK_PCI_DSS)
	}
}

func TestPIIComplianceMapping_Completeness(t *testing.T) {
	// Verify all PII categories have compliance mappings
	allCategories := []PIICategory{
		PII_SSN,
		PII_CREDIT_CARD,
		PII_EMAIL,
		PII_PHONE,
		PII_HEALTH,
		PII_PASSPORT,
		PII_DRIVER_LICENSE,
		PII_BANK_ACCOUNT,
		PII_IP_ADDRESS,
		PII_DATE_OF_BIRTH,
		PII_NAME,
		PII_ADDRESS,
	}

	for _, category := range allCategories {
		mappings := PIIComplianceMapping[category]
		if len(mappings) == 0 {
			t.Errorf("PII category %s has no compliance mappings", category)
		}
	}
}

func TestMapPIIToFrameworks_Severity(t *testing.T) {
	// High severity PII should produce high severity violations
	highSeverityPII := []PIICategory{
		PII_SSN,
		PII_CREDIT_CARD,
		PII_HEALTH,
		PII_BANK_ACCOUNT,
	}

	for _, category := range highSeverityPII {
		match := PIIMatch{
			Category: category,
			Value:    "test",
			Severity: 5,
		}

		violations := MapPIIToFrameworks(match)
		for _, v := range violations {
			if v.Severity < 4 {
				t.Errorf("Expected high severity violation for %s, got %d", category, v.Severity)
			}
		}
	}
}

func TestGenerateComplianceReports_ControlIDs(t *testing.T) {
	matches := []PIIMatch{
		{
			Category: PII_HEALTH,
			Value:    "MRN12345",
			Severity: 5,
		},
	}

	reports := GenerateComplianceReports(matches)

	hipaaReport, exists := reports["HIPAA"]
	if !exists {
		t.Fatal("Expected HIPAA report")
	}

	// HIPAA should have specific control IDs like 164.312
	hasHIPAAControl := false
	for _, v := range hipaaReport.Violations {
		if len(v) > 0 && v[0] == '1' {
			hasHIPAAControl = true
			break
		}
	}

	if !hasHIPAAControl {
		t.Error("Expected HIPAA report to have HIPAA control IDs (e.g., 164.312)")
	}
}
