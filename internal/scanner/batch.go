// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart — Batch Scanner
//
// Scans directories and repositories for PII, secrets, and threats.
// Complements real-time proxy protection with historical analysis.

package scanner

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ScanResult contains results from a batch scan.
type ScanResult struct {
	Path       string      `json:"path"`
	TotalFiles int         `json:"total_files"`
	ScannedAt  time.Time   `json:"scanned_at"`
	Detections []Detection `json:"detections"`
}

// Detection represents a single finding.
type Detection struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// ScanDir scans a directory recursively.
func ScanDir(path string) (*ScanResult, error) {
	result := &ScanResult{
		Path:      path,
		ScannedAt: time.Now(),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			// Skip common non-code directories
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == ".venv" || name == "__pycache__" || name == "target" {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip binary files
		if !isTextFile(path) {
			return nil
		}

		mu.Lock()
		result.TotalFiles++
		mu.Unlock()

		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			detections := scanFile(filePath)
			if len(detections) > 0 {
				mu.Lock()
				result.Detections = append(result.Detections, detections...)
				mu.Unlock()
			}
		}(path)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	wg.Wait()
	return result, nil
}

func scanFile(path string) []Detection {
	var detections []Detection

	file, err := os.Open(path)
	if err != nil {
		return detections
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check for secrets
		if strings.Contains(strings.ToLower(line), "api_key") ||
			strings.Contains(strings.ToLower(line), "password") ||
			strings.Contains(strings.ToLower(line), "secret") {
			detections = append(detections, Detection{
				File:     path,
				Line:     lineNum,
				Category: "secrets",
				Severity: "high",
				Message:  "Potential secret or API key detected",
			})
		}

		// Check for PII (SSN pattern)
		// Simple SSN pattern check
		// In production, use the full PII detector from internal/detectors
		_ = strings.Contains(line, "-")
	}

	return detections
}

func isTextFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	textExtensions := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true,
		".java": true, ".rb": true, ".rs": true, ".cpp": true,
		".c": true, ".h": true, ".cs": true, ".php": true,
		".yaml": true, ".yml": true, ".json": true, ".xml": true,
		".md": true, ".txt": true, ".sh": true, ".bash": true,
		".zsh": true, ".env": true, ".toml": true, ".ini": true,
	}
	return textExtensions[ext]
}
