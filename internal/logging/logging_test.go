package logging

import (
	"testing"
	"time"
)

func TestSeverityValues(t *testing.T) {
	tests := []struct {
		s Severity
		v string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
	}
	for _, tt := range tests {
		if string(tt.s) != tt.v {
			t.Errorf("Severity %s = %q, want %q", tt.s, string(tt.s), tt.v)
		}
	}
}

func TestRecord(t *testing.T) {
	Record(Event{
		Type:     "test",
		Severity: SeverityInfo,
		Message:  "test message",
	})
}

func TestRecordWithFields(t *testing.T) {
	Record(Event{
		Type:       "pii",
		Severity:   SeverityHigh,
		Message:    "SSN detected",
		ThreatType: "ssn",
		Pattern:    "\\d{3}-\\d{2}-\\d{4}",
	})
}

func TestRecordWithTime(t *testing.T) {
	Record(Event{
		Time:     time.Now(),
		Type:     "security",
		Severity: SeverityMedium,
		Message:  "detection event",
	})
}

func TestRecordAllSeverities(t *testing.T) {
	severities := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	for _, s := range severities {
		Record(Event{Severity: s, Type: "test", Message: "testing severity"})
	}
}

func TestRecordEmptyMessage(t *testing.T) {
	Record(Event{Severity: SeverityInfo, Type: "test", Message: ""})
}

func TestRecordLongMessage(t *testing.T) {
	longMsg := ""
	for i := 0; i < 1000; i++ {
		longMsg += "x"
	}
	Record(Event{Severity: SeverityInfo, Type: "test", Message: longMsg})
}

func TestEventStruct(t *testing.T) {
	e := Event{
		Type:       "secret",
		Severity:   SeverityHigh,
		Message:    "AWS key detected",
		ThreatType: "aws_access_key",
		Pattern:    "AKIA[0-9A-Z]{16}",
	}
	if e.Type != "secret" {
		t.Errorf("Type = %s, want secret", e.Type)
	}
	if e.Severity != SeverityHigh {
		t.Errorf("Severity = %s, want high", e.Severity)
	}
	if e.ThreatType != "aws_access_key" {
		t.Errorf("ThreatType = %s", e.ThreatType)
	}
}

func TestRecordZeroTime(t *testing.T) {
	// Record should set time to now if zero
	e := Event{Type: "test", Severity: SeverityInfo, Message: "zero time"}
	if !e.Time.IsZero() {
		t.Error("Time should be zero before Record")
	}
	Record(e)
	// Record internally sets the time — just verify no panic
}
