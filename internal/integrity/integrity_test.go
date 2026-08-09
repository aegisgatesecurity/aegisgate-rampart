// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Config Integrity Tests
// =========================================================================

package integrity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewVerifier(t *testing.T) {
	v := NewVerifier(false)
	if v == nil {
		t.Fatal("Expected verifier instance, got nil")
	}
	if v.strictMode {
		t.Error("Expected strictMode to be false")
	}
	if v.hashAlgo != "sha256" {
		t.Errorf("Expected hashAlgo sha256, got %s", v.hashAlgo)
	}

	vStrict := NewVerifier(true)
	if !vStrict.strictMode {
		t.Error("Expected strictMode to be true")
	}
}

func TestComputeHash(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	testConfig := `{"mode": "block", "port": 8080}`

	if err := os.WriteFile(configPath, []byte(testConfig), 0644); err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	v := NewVerifier(false)
	hash, err := v.ComputeHash(configPath)

	if err != nil {
		t.Fatalf("ComputeHash failed: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("Expected 64-char hex hash, got %d chars", len(hash))
	}
	if !isHex(hash) {
		t.Error("Hash is not valid hex")
	}
}

func TestComputeHash_FileNotFound(t *testing.T) {
	v := NewVerifier(false)
	_, err := v.ComputeHash("/nonexistent/config.json")

	if err == nil {
		t.Fatal("Expected error for missing file")
	}
	if !strings.Contains(err.Error(), "opening config file") {
		t.Errorf("Expected open error, got: %v", err)
	}
}

func TestGenerateHashRecord(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test configs
	config1 := filepath.Join(tmpDir, "config1.json")
	config2 := filepath.Join(tmpDir, "config2.json")
	os.WriteFile(config1, []byte(`{"mode": "block"}`), 0644)
	os.WriteFile(config2, []byte(`{"mode": "monitor"}`), 0644)

	v := NewVerifier(false)
	record, err := v.GenerateHashRecord([]string{config1, config2}, "test record")

	if err != nil {
		t.Fatalf("GenerateHashRecord failed: %v", err)
	}
	if record.Version != 1 {
		t.Errorf("Expected version 1, got %d", record.Version)
	}
	if record.Algorithm != "sha256" {
		t.Errorf("Expected algorithm sha256, got %s", record.Algorithm)
	}
	if len(record.Configs) != 2 {
		t.Errorf("Expected 2 configs, got %d", len(record.Configs))
	}
	if record.Comment != "test record" {
		t.Errorf("Expected comment 'test record', got %s", record.Comment)
	}

	// Verify each config has required fields
	for _, config := range record.Configs {
		if config.Hash == "" {
			t.Error("Expected hash to be set")
		}
		if config.FileSize == 0 {
			t.Error("Expected file size to be set")
		}
		if config.HashAlgo != "sha256" {
			t.Errorf("Expected hashAlgo sha256, got %s", config.HashAlgo)
		}
	}
}

func TestGenerateHashRecord_MissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, []byte(`{}`), 0644)

	// Non-strict mode: skip missing files
	v := NewVerifier(false)
	record, err := v.GenerateHashRecord([]string{configPath, "/nonexistent.json"}, "")

	if err != nil {
		t.Fatalf("GenerateHashRecord failed in non-strict mode: %v", err)
	}
	if len(record.Configs) != 1 {
		t.Errorf("Expected 1 config (missing skipped), got %d", len(record.Configs))
	}

	// Strict mode: fail on missing files
	vStrict := NewVerifier(true)
	_, err = vStrict.GenerateHashRecord([]string{configPath, "/nonexistent.json"}, "")

	if err == nil {
		t.Fatal("Expected error in strict mode")
	}
}

func TestVerifyHash_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	testConfig := `{"mode": "block"}`
	os.WriteFile(configPath, []byte(testConfig), 0644)

	v := NewVerifier(false)
	expectedHash, _ := v.ComputeHash(configPath)

	result, err := v.VerifyHash(configPath, expectedHash)

	if err != nil {
		t.Fatalf("VerifyHash failed: %v", err)
	}
	if !result.Valid {
		t.Error("Expected hash to be valid")
	}
	if result.ComputedSHA != expectedHash {
		t.Error("Expected computed hash to match")
	}
	if result.Metadata == nil {
		t.Error("Expected metadata to be set")
	}
}

func TestVerifyHash_Invalid(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, []byte(`{"mode": "block"}`), 0644)

	v := NewVerifier(false)
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"

	result, err := v.VerifyHash(configPath, wrongHash)

	if err == nil {
		t.Fatal("Expected error for invalid hash")
	}
	if result.Valid {
		t.Error("Expected hash to be invalid")
	}
	if !strings.Contains(err.Error(), "integrity check failed") {
		t.Errorf("Expected integrity error, got: %v", err)
	}
}

func TestSaveAndLoadHashRecord(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	recordPath := filepath.Join(tmpDir, "hashes.json")
	os.WriteFile(configPath, []byte(`{}`), 0644)

	v := NewVerifier(false)
	record, _ := v.GenerateHashRecord([]string{configPath}, "test")

	// Save
	err := v.SaveHashRecord(record, recordPath)
	if err != nil {
		t.Fatalf("SaveHashRecord failed: %v", err)
	}

	// Load
	loaded, err := v.LoadHashRecord(recordPath)
	if err != nil {
		t.Fatalf("LoadHashRecord failed: %v", err)
	}

	// Verify
	if loaded.Version != record.Version {
		t.Errorf("Version mismatch: %d vs %d", loaded.Version, record.Version)
	}
	if len(loaded.Configs) != len(record.Configs) {
		t.Errorf("Config count mismatch: %d vs %d", len(loaded.Configs), len(record.Configs))
	}
	if loaded.Comment != record.Comment {
		t.Errorf("Comment mismatch: %s vs %s", loaded.Comment, record.Comment)
	}
}

func TestLoadHashRecord_InvalidVersion(t *testing.T) {
	tmpDir := t.TempDir()
	recordPath := filepath.Join(tmpDir, "hashes.json")

	// Create invalid record
	invalid := map[string]interface{}{
		"version":   99,
		"algorithm": "sha256",
		"configs":   []interface{}{},
	}
	data, _ := json.Marshal(invalid)
	os.WriteFile(recordPath, data, 0644)

	v := NewVerifier(false)
	_, err := v.LoadHashRecord(recordPath)

	if err == nil {
		t.Fatal("Expected error for invalid version")
	}
	if !strings.Contains(err.Error(), "unsupported record version") {
		t.Errorf("Expected version error, got: %v", err)
	}
}

func TestDetectChanges_Unchanged(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, []byte(`{"mode": "block"}`), 0644)

	v := NewVerifier(false)
	record, _ := v.GenerateHashRecord([]string{configPath}, "")

	report, err := v.DetectChanges(record)

	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if !report.IsSecure() {
		t.Error("Expected report to be secure")
	}
	if report.Summary.Unchanged != 1 {
		t.Errorf("Expected 1 unchanged, got %d", report.Summary.Unchanged)
	}
	if report.Summary.Modified != 0 {
		t.Errorf("Expected 0 modified, got %d", report.Summary.Modified)
	}
}

func TestDetectChanges_Modified(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, []byte(`{"mode": "block"}`), 0644)

	v := NewVerifier(false)
	record, _ := v.GenerateHashRecord([]string{configPath}, "")

	// Modify config
	os.WriteFile(configPath, []byte(`{"mode": "monitor"}`), 0644)

	report, err := v.DetectChanges(record)

	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if report.IsSecure() {
		t.Error("Expected report to be insecure (modified)")
	}
	if report.Summary.Modified != 1 {
		t.Errorf("Expected 1 modified, got %d", report.Summary.Modified)
	}
}

func TestDetectChanges_Missing(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, []byte(`{}`), 0644)

	v := NewVerifier(false)
	record, _ := v.GenerateHashRecord([]string{configPath}, "")

	// Delete config
	os.Remove(configPath)

	report, err := v.DetectChanges(record)

	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if report.IsSecure() {
		t.Error("Expected report to be insecure (missing)")
	}
	if report.Summary.Missing != 1 {
		t.Errorf("Expected 1 missing, got %d", report.Summary.Missing)
	}
}

func TestChangeStatus_String(t *testing.T) {
	tests := []struct {
		status   ChangeStatus
		expected string
	}{
		{ChangeUnchanged, "unchanged"},
		{ChangeModified, "modified"},
		{ChangeMissing, "missing"},
		{ChangeError, "error"},
		{ChangeStatus(99), "unknown"},
	}

	for _, tt := range tests {
		if tt.status.String() != tt.expected {
			t.Errorf("Status %d: expected %s, got %s", tt.status, tt.expected, tt.status.String())
		}
	}
}

func TestHashRecord_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, []byte(`{}`), 0644)

	v := NewVerifier(false)
	record, _ := v.GenerateHashRecord([]string{configPath}, "test")

	// Marshal to JSON
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	// Verify JSON structure
	var check map[string]interface{}
	if err := json.Unmarshal(data, &check); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	if check["version"] != float64(1) {
		t.Error("Expected version in JSON")
	}
	if check["algorithm"] != "sha256" {
		t.Error("Expected algorithm in JSON")
	}
	if _, ok := check["configs"].([]interface{}); !ok {
		t.Error("Expected configs array in JSON")
	}
}

func TestVerifyHash_CaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, []byte(`{}`), 0644)

	v := NewVerifier(false)
	hash, _ := v.ComputeHash(configPath)

	// Test with uppercase
	result, err := v.VerifyHash(configPath, strings.ToUpper(hash))
	if err != nil {
		t.Fatalf("VerifyHash failed with uppercase: %v", err)
	}
	if !result.Valid {
		t.Error("Expected uppercase hash to be valid")
	}

	// Test with lowercase
	result, err = v.VerifyHash(configPath, strings.ToLower(hash))
	if err != nil {
		t.Fatalf("VerifyHash failed with lowercase: %v", err)
	}
	if !result.Valid {
		t.Error("Expected lowercase hash to be valid")
	}
}

func TestGenerateHashRecord_Empty(t *testing.T) {
	v := NewVerifier(false)
	record, err := v.GenerateHashRecord([]string{}, "")

	if err != nil {
		t.Fatalf("GenerateHashRecord failed: %v", err)
	}
	if len(record.Configs) != 0 {
		t.Errorf("Expected 0 configs, got %d", len(record.Configs))
	}
}

func TestDetectChanges_MultipleConfigs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple configs
	configs := make([]string, 5)
	for i := 0; i < 5; i++ {
		configs[i] = filepath.Join(tmpDir, "config"+string(rune('0'+i))+".json")
		os.WriteFile(configs[i], []byte(`{}`), 0644)
	}

	v := NewVerifier(false)
	record, _ := v.GenerateHashRecord(configs, "")

	// Modify 2, delete 1, leave 2 unchanged
	os.WriteFile(configs[0], []byte(`{"changed": true}`), 0644)
	os.WriteFile(configs[1], []byte(`{"changed": true}`), 0644)
	os.Remove(configs[2])

	report, err := v.DetectChanges(record)

	if err != nil {
		t.Fatalf("DetectChanges failed: %v", err)
	}
	if report.Summary.Modified != 2 {
		t.Errorf("Expected 2 modified, got %d", report.Summary.Modified)
	}
	if report.Summary.Missing != 1 {
		t.Errorf("Expected 1 missing, got %d", report.Summary.Missing)
	}
	if report.Summary.Unchanged != 2 {
		t.Errorf("Expected 2 unchanged, got %d", report.Summary.Unchanged)
	}
	if report.IsSecure() {
		t.Error("Expected report to be insecure")
	}
}

// Helper functions

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
