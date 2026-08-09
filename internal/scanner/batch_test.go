// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart — Batch Scanner Tests

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanDir_EmptyDirectory(t *testing.T) {
	// Create a temporary empty directory
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	if result.TotalFiles != 0 {
		t.Errorf("Expected 0 files in empty directory, got %d", result.TotalFiles)
	}
	if len(result.Detections) != 0 {
		t.Errorf("Expected 0 detections in empty directory, got %d", len(result.Detections))
	}
	if result.Path != tmpDir {
		t.Errorf("Expected path %q, got %q", tmpDir, result.Path)
	}
	if result.ScannedAt.IsZero() {
		t.Error("ScannedAt should be set")
	}
}

func TestScanDir_NoDetections(t *testing.T) {
	// Create a temporary directory with clean files
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a clean Go file
	cleanCode := `package main

func main() {
	println("Hello, World!")
}
`
	err = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(cleanCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 file, got %d", result.TotalFiles)
	}
	if len(result.Detections) != 0 {
		t.Errorf("Expected 0 detections in clean file, got %d", len(result.Detections))
	}
}

func TestScanDir_DetectSecrets(t *testing.T) {
	// Create a temporary directory with files containing secrets
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a file with secrets
	secretCode := `package config

var (
	api_key = "sk-1234567890abcdef"
	password = "supersecret123"
	secret_token = "ghp_xxxxxxxxxxxx"
)
`
	err = os.WriteFile(filepath.Join(tmpDir, "config.go"), []byte(secretCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 file, got %d", result.TotalFiles)
	}
	if len(result.Detections) == 0 {
		t.Error("Expected detections in file with secrets")
	}

	// Verify detection details
	for _, detection := range result.Detections {
		if detection.Category != "secrets" {
			t.Errorf("Expected category 'secrets', got %q", detection.Category)
		}
		if detection.Severity != "high" {
			t.Errorf("Expected severity 'high', got %q", detection.Severity)
		}
		if detection.File != filepath.Join(tmpDir, "config.go") {
			t.Errorf("Expected file path %q, got %q", filepath.Join(tmpDir, "config.go"), detection.File)
		}
		if detection.Line <= 0 {
			t.Errorf("Expected positive line number, got %d", detection.Line)
		}
	}
}

func TestScanDir_SkipsGitDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create .git directory with files
	gitDir := filepath.Join(tmpDir, ".git")
	err = os.MkdirAll(gitDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create .git dir: %v", err)
	}
	err = os.WriteFile(filepath.Join(gitDir, "config"), []byte("secret=data"), 0644)
	if err != nil {
		t.Fatalf("Failed to write git config: %v", err)
	}

	// Create a normal file
	err = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	// Should only scan main.go, not .git/config
	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 file (skipping .git), got %d", result.TotalFiles)
	}
}

func TestScanDir_SkipsNodeModules(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create node_modules directory
	nodeDir := filepath.Join(tmpDir, "node_modules")
	err = os.MkdirAll(nodeDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create node_modules dir: %v", err)
	}
	err = os.WriteFile(filepath.Join(nodeDir, "package.json"), []byte(`{"name":"test"}`), 0644)
	if err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	// Create a normal file
	err = os.WriteFile(filepath.Join(tmpDir, "index.js"), []byte("console.log('hi')"), 0644)
	if err != nil {
		t.Fatalf("Failed to write index.js: %v", err)
	}

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	// Should only scan index.js, not node_modules
	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 file (skipping node_modules), got %d", result.TotalFiles)
	}
}

func TestScanDir_SkipsBinaryFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a binary file (PNG header)
	binaryData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	err = os.WriteFile(filepath.Join(tmpDir, "image.png"), binaryData, 0644)
	if err != nil {
		t.Fatalf("Failed to write binary file: %v", err)
	}

	// Create a text file
	err = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("hello"), 0644)
	if err != nil {
		t.Fatalf("Failed to write text file: %v", err)
	}

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	// Should skip binary file, only count text file
	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 text file (skipping binary), got %d", result.TotalFiles)
	}
}

func TestIsTextFile(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"main.go", true},
		{"script.py", true},
		{"app.js", true},
		{"index.ts", true},
		{"config.yaml", true},
		{"config.yml", true},
		{"data.json", true},
		{"README.md", true},
		{"notes.txt", true},
		{"script.sh", true},
		{"image.png", false},
		{"binary.exe", false},
		{"photo.jpg", false},
		{"archive.zip", false},
		{"library.so", false},
		{"binary", false}, // no extension
	}

	for _, test := range tests {
		t.Run(test.filename, func(t *testing.T) {
			result := isTextFile(filepath.Join("/tmp", test.filename))
			if result != test.expected {
				t.Errorf("isTextFile(%q) = %v, expected %v", test.filename, result, test.expected)
			}
		})
	}
}

func TestScanFile_DetectionLineNumbers(t *testing.T) {
	// Create a temporary directory (not file) to avoid scanning other files
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write file with secrets on lines 3 and 7
	content := `package test

// Line 3: api_key detected
var key = "api_key=12345"

// Line 6: clean

// Line 8: password detected
var pass = "password=secret"
`
	testFile := filepath.Join(tmpDir, "test.go")
	err = os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write content: %v", err)
	}

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	if len(result.Detections) < 2 {
		t.Errorf("Expected at least 2 detections, got %d", len(result.Detections))
	}
}

func TestScanResult_JSONSerializable(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a file with a secret
	err = os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte("var api_key = 'secret'"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	// Verify all fields are populated for JSON serialization
	if result.Path == "" {
		t.Error("Path should be set")
	}
	if result.TotalFiles == 0 {
		t.Error("TotalFiles should be > 0")
	}
	if result.ScannedAt.IsZero() {
		t.Error("ScannedAt should be set")
	}
	if len(result.Detections) == 0 {
		t.Error("Detections should not be empty")
	}

	// Verify detection fields
	for i, detection := range result.Detections {
		if detection.File == "" {
			t.Errorf("Detection %d: File should be set", i)
		}
		if detection.Line <= 0 {
			t.Errorf("Detection %d: Line should be positive", i)
		}
		if detection.Category == "" {
			t.Errorf("Detection %d: Category should be set", i)
		}
		if detection.Severity == "" {
			t.Errorf("Detection %d: Severity should be set", i)
		}
		if detection.Message == "" {
			t.Errorf("Detection %d: Message should be set", i)
		}
	}
}

func TestScanDir_NestedDirectories(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create nested structure
	subDir := filepath.Join(tmpDir, "subdir", "nested")
	err = os.MkdirAll(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create nested dirs: %v", err)
	}

	// Create files at different levels
	_ = os.WriteFile(filepath.Join(tmpDir, "root.go"), []byte("package root"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "subdir", "sub.go"), []byte("package sub"), 0644)
	_ = os.WriteFile(filepath.Join(subDir, "nested.go"), []byte("var api_key = 'secret'"), 0644)

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	if result.TotalFiles != 3 {
		t.Errorf("Expected 3 files in nested structure, got %d", result.TotalFiles)
	}

	// Should detect secret in nested file
	if len(result.Detections) == 0 {
		t.Error("Expected detections in nested structure")
	}
}

func TestScanDir_CaseInsensitiveSecretDetection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test case variations
	content := `API_KEY = "secret1"
ApiKey = "secret2"
api_Key = "secret3"
PaSsWoRd = "secret4"
SECRET = "secret5"
`
	err = os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	// Should detect all variations (case-insensitive)
	if len(result.Detections) < 3 {
		t.Errorf("Expected at least 3 detections for case variations, got %d", len(result.Detections))
	}
}

func TestScanFile_EmptyFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create empty file
	err = os.WriteFile(filepath.Join(tmpDir, "empty.go"), []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to write empty file: %v", err)
	}

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	if result.TotalFiles != 1 {
		t.Errorf("Expected 1 file, got %d", result.TotalFiles)
	}
	if len(result.Detections) != 0 {
		t.Errorf("Expected 0 detections in empty file, got %d", len(result.Detections))
	}
}

func TestScanDir_Symlinks(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a real file
	realFile := filepath.Join(tmpDir, "real.go")
	err = os.WriteFile(realFile, []byte("package main"), 0644)
	if err != nil {
		t.Fatalf("Failed to write real file: %v", err)
	}

	// Create symlink
	symlinkPath := filepath.Join(tmpDir, "link.go")
	err = os.Symlink(realFile, symlinkPath)
	if err != nil {
		// Skip test if symlinks not supported (Windows)
		t.Skip("Symlinks not supported on this platform")
	}

	result, err := ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}

	// Should handle symlinks gracefully
	if result.TotalFiles < 1 {
		t.Errorf("Expected at least 1 file, got %d", result.TotalFiles)
	}
}

func TestScanDir_PermDenied(t *testing.T) {
	// This test may not work in all environments
	tmpDir, err := os.MkdirTemp("", "rampart-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a file and remove read permissions
	noPermFile := filepath.Join(tmpDir, "noperm.go")
	err = os.WriteFile(noPermFile, []byte("package main"), 0644)
	if err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}
	
	// Try to remove permissions (may not work on all systems)
	err = os.Chmod(noPermFile, 0000)
	if err != nil {
		t.Skip("Cannot change permissions on this platform")
	}
	defer func() { _ = os.Chmod(noPermFile, 0644) }()

	_, err = ScanDir(tmpDir)
	// Should handle permission errors gracefully
	if err == nil {
		// If no error, that's also acceptable (running as root)
		t.Log("ScanDir handled permission-denied gracefully")
	}
}
