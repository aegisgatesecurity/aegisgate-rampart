// SPDX-License-Identifier: Apache-2.0
// Test coverage for integrity VerifyHashRecord function

package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyHashRecord(t *testing.T) {
	// Create temp dir with test config files
	tmpDir := t.TempDir()
	config1 := filepath.Join(tmpDir, "config1.yaml")
	config2 := filepath.Join(tmpDir, "config2.yaml")
	if err := os.WriteFile(config1, []byte("key: value1\n"), 0644); err != nil {
		t.Fatalf("write config1: %v", err)
	}
	if err := os.WriteFile(config2, []byte("key: value2\n"), 0644); err != nil {
		t.Fatalf("write config2: %v", err)
	}

	v := NewVerifier(false)

	// Generate hash record
	record, err := v.GenerateHashRecord([]string{config1, config2}, "test record")
	if err != nil {
		t.Fatalf("GenerateHashRecord failed: %v", err)
	}

	// Verify all valid
	results, err := v.VerifyHashRecord(record)
	if err != nil {
		t.Errorf("VerifyHashRecord with valid configs should not error: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.Valid {
			t.Errorf("Expected valid for valid config, got invalid")
		}
	}

	// Modify one file and verify
	if err := os.WriteFile(config2, []byte("key: modified\n"), 0644); err != nil {
		t.Fatalf("write config2 modified: %v", err)
	}
	results, err = v.VerifyHashRecord(record)
	if err != nil {
		// Non-strict mode should not error
		t.Errorf("VerifyHashRecord in non-strict mode should not error: %v", err)
	}
	mismatchCount := 0
	for _, r := range results {
		if !r.Valid {
			mismatchCount++
		}
	}
	if mismatchCount != 1 {
		t.Errorf("Expected 1 mismatch, got %d", mismatchCount)
	}

	// Test with strict mode
	strictV := NewVerifier(true)
	_, err = strictV.VerifyHashRecord(record)
	if err == nil {
		t.Error("VerifyHashRecord in strict mode with mismatch should error")
	}
}

func TestVerifyHashRecord_AllValid(t *testing.T) {
	tmpDir := t.TempDir()
	config := filepath.Join(tmpDir, "app.conf")
	if err := os.WriteFile(config, []byte("port=8080\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	v := NewVerifier(true)
	record, err := v.GenerateHashRecord([]string{config}, "single config")
	if err != nil {
		t.Fatalf("GenerateHashRecord failed: %v", err)
	}

	results, err := v.VerifyHashRecord(record)
	if err != nil {
		t.Errorf("VerifyHashRecord with all valid in strict mode should not error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
}
