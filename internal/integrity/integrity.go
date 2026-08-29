// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Config File Integrity
// =========================================================================
//
// Provides SHA-256 hash verification for configuration files to detect
// unauthorized modifications, tampering, or silent downgrades.
//
// Usage:
//   1. Generate hash: rampart config-hash --config /path/to/config.json
//   2. Store hash securely (separate from config)
//   3. Verify: rampart config-verify --config /path/to/config.json --hash <expected>
//   4. Or verify against stored hash file
// =========================================================================

package integrity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// IntegrityResult represents the result of integrity verification
type IntegrityResult struct {
	Valid       bool
	ConfigPath  string
	ComputedSHA string
	ExpectedSHA string
	Timestamp   time.Time
	Metadata    *ConfigMetadata
	Error       error
}

// ConfigMetadata contains metadata about the configuration
type ConfigMetadata struct {
	FilePath    string    `json:"file_path"`
	FileSize    int64     `json:"file_size"`
	ModTime     time.Time `json:"mod_time"`
	Permissions string    `json:"permissions"`
	HashAlgo    string    `json:"hash_algorithm"`
	Hash        string    `json:"hash"`
	GeneratedAt time.Time `json:"generated_at"`
}

// HashRecord represents a stored hash record (JSON format)
type HashRecord struct {
	Version   int              `json:"version"`
	Algorithm string           `json:"algorithm"`
	Configs   []ConfigMetadata `json:"configs"`
	Generated time.Time        `json:"generated"`
	Comment   string           `json:"comment,omitempty"`
}

// Verifier provides config integrity verification services
type Verifier struct {
	strictMode bool
	hashAlgo   string
}

// NewVerifier creates a new config integrity verifier
func NewVerifier(strictMode bool) *Verifier {
	return &Verifier{
		strictMode: strictMode,
		hashAlgo:   "sha256",
	}
}

// ComputeHash computes SHA-256 hash of a config file
func (v *Verifier) ComputeHash(configPath string) (string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return "", fmt.Errorf("opening config file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("computing hash: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// GenerateHashRecord creates a hash record for one or more config files
func (v *Verifier) GenerateHashRecord(configPaths []string, comment string) (*HashRecord, error) {
	record := &HashRecord{
		Version:   1,
		Algorithm: v.hashAlgo,
		Configs:   make([]ConfigMetadata, 0, len(configPaths)),
		Generated: time.Now(),
		Comment:   comment,
	}

	for _, configPath := range configPaths {
		// Compute hash
		hash, err := v.ComputeHash(configPath)
		if err != nil {
			if v.strictMode {
				return nil, fmt.Errorf("computing hash for %s: %w", configPath, err)
			}
			// In non-strict mode, skip missing files
			continue
		}

		// Get file metadata
		info, err := os.Stat(configPath)
		if err != nil {
			if v.strictMode {
				return nil, fmt.Errorf("stat %s: %w", configPath, err)
			}
			continue
		}

		metadata := ConfigMetadata{
			FilePath:    configPath,
			FileSize:    info.Size(),
			ModTime:     info.ModTime(),
			Permissions: fmt.Sprintf("%o", info.Mode().Perm()),
			HashAlgo:    v.hashAlgo,
			Hash:        hash,
			GeneratedAt: time.Now(),
		}

		record.Configs = append(record.Configs, metadata)
	}

	return record, nil
}

// VerifyHash verifies a config file against an expected hash
func (v *Verifier) VerifyHash(configPath, expectedHash string) (*IntegrityResult, error) {
	result := &IntegrityResult{
		ConfigPath:  configPath,
		ExpectedSHA: expectedHash,
		Timestamp:   time.Now(),
	}

	// Compute actual hash
	computedHash, err := v.ComputeHash(configPath)
	if err != nil {
		result.Error = fmt.Errorf("computing hash: %w", err)
		return result, result.Error
	}
	result.ComputedSHA = computedHash

	// Get metadata
	info, err := os.Stat(configPath)
	if err == nil {
		result.Metadata = &ConfigMetadata{
			FilePath:    configPath,
			FileSize:    info.Size(),
			ModTime:     info.ModTime(),
			Permissions: fmt.Sprintf("%o", info.Mode().Perm()),
			HashAlgo:    v.hashAlgo,
			Hash:        computedHash,
			GeneratedAt: time.Now(),
		}
	}

	// Compare hashes (case-insensitive)
	// MEDIUM-12 FIX: use constant-time comparison to prevent timing side-channels
	if subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(expectedHash)),
		[]byte(strings.ToLower(computedHash)),
	) != 1 {
		result.Valid = false
		result.Error = fmt.Errorf("integrity check failed: config file has been modified")
		return result, result.Error
	}

	result.Valid = true
	return result, nil
}

// VerifyHashRecord verifies multiple config files against a hash record
func (v *Verifier) VerifyHashRecord(record *HashRecord) ([]IntegrityResult, error) {
	results := make([]IntegrityResult, 0, len(record.Configs))
	hasFailure := false

	for _, config := range record.Configs {
		result, err := v.VerifyHash(config.FilePath, config.Hash)
		results = append(results, *result)
		if err != nil {
			hasFailure = true
		}
	}

	if hasFailure && v.strictMode {
		return results, fmt.Errorf("one or more config files failed integrity check")
	}

	return results, nil
}

// SaveHashRecord saves a hash record to a JSON file
func (v *Verifier) SaveHashRecord(record *HashRecord, outputPath string) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling record: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil { // LOW-6 FIX: restrict to owner-only
		return fmt.Errorf("writing record: %w", err)
	}

	return nil
}

// LoadHashRecord loads a hash record from a JSON file
func (v *Verifier) LoadHashRecord(recordPath string) (*HashRecord, error) {
	data, err := os.ReadFile(recordPath)
	if err != nil {
		return nil, fmt.Errorf("reading record: %w", err)
	}

	var record HashRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("parsing record: %w", err)
	}

	// Validate version
	if record.Version != 1 {
		return nil, fmt.Errorf("unsupported record version: %d", record.Version)
	}

	// Validate algorithm
	if record.Algorithm != "sha256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", record.Algorithm)
	}

	return &record, nil
}

// DetectChanges compares current config state against a hash record
func (v *Verifier) DetectChanges(record *HashRecord) (*ChangeReport, error) {
	report := &ChangeReport{
		Timestamp: time.Now(),
		Configs:   make([]ConfigChange, 0),
		Summary:   ChangeSummary{},
	}

	for _, expected := range record.Configs {
		change := ConfigChange{
			Path:       expected.FilePath,
			Expected:   expected,
			DetectedAt: time.Now(),
		}

		// Check if file exists
		info, err := os.Stat(expected.FilePath)
		if os.IsNotExist(err) {
			change.Status = ChangeMissing
			change.Detected = &ConfigMetadata{
				FilePath: expected.FilePath,
			}
			report.Configs = append(report.Configs, change)
			report.Summary.Missing++
			continue
		}
		if err != nil {
			change.Status = ChangeError
			change.Error = err
			report.Configs = append(report.Configs, change)
			report.Summary.Errors++
			continue
		}

		// Compute current hash
		currentHash, err := v.ComputeHash(expected.FilePath)
		if err != nil {
			change.Status = ChangeError
			change.Error = err
			report.Configs = append(report.Configs, change)
			report.Summary.Errors++
			continue
		}

		// Compare
		// MEDIUM-12 FIX: use constant-time comparison
		if subtle.ConstantTimeCompare(
			[]byte(strings.ToLower(expected.Hash)),
			[]byte(strings.ToLower(currentHash)),
		) == 1 {
			change.Status = ChangeUnchanged
			change.Detected = &ConfigMetadata{
				FilePath:    expected.FilePath,
				FileSize:    info.Size(),
				ModTime:     info.ModTime(),
				Permissions: fmt.Sprintf("%o", info.Mode().Perm()),
				HashAlgo:    v.hashAlgo,
				Hash:        currentHash,
				GeneratedAt: time.Now(),
			}
			report.Summary.Unchanged++
		} else {
			change.Status = ChangeModified
			change.Detected = &ConfigMetadata{
				FilePath:    expected.FilePath,
				FileSize:    info.Size(),
				ModTime:     info.ModTime(),
				Permissions: fmt.Sprintf("%o", info.Mode().Perm()),
				HashAlgo:    v.hashAlgo,
				Hash:        currentHash,
				GeneratedAt: time.Now(),
			}
			report.Summary.Modified++
		}

		report.Configs = append(report.Configs, change)
	}

	return report, nil
}

// ChangeStatus represents the status of a config file change
type ChangeStatus int

const (
	ChangeUnchanged ChangeStatus = iota
	ChangeModified
	ChangeMissing
	ChangeError
)

func (s ChangeStatus) String() string {
	switch s {
	case ChangeUnchanged:
		return "unchanged"
	case ChangeModified:
		return "modified"
	case ChangeMissing:
		return "missing"
	case ChangeError:
		return "error"
	default:
		return "unknown"
	}
}

// ConfigChange represents a change detected in a config file
type ConfigChange struct {
	Path       string          `json:"path"`
	Status     ChangeStatus    `json:"status"`
	Expected   ConfigMetadata  `json:"expected"`
	Detected   *ConfigMetadata `json:"detected,omitempty"`
	Error      error           `json:"error,omitempty"`
	DetectedAt time.Time       `json:"detected_at"`
}

// ChangeSummary provides a summary of changes
type ChangeSummary struct {
	Total     int `json:"total"`
	Unchanged int `json:"unchanged"`
	Modified  int `json:"modified"`
	Missing   int `json:"missing"`
	Errors    int `json:"errors"`
}

// ChangeReport represents a complete change detection report
type ChangeReport struct {
	Timestamp time.Time      `json:"timestamp"`
	Configs   []ConfigChange `json:"configs"`
	Summary   ChangeSummary  `json:"summary"`
}

// IsSecure returns true if no unauthorized changes detected
func (r *ChangeReport) IsSecure() bool {
	return r.Summary.Modified == 0 && r.Summary.Missing == 0 && r.Summary.Errors == 0
}
