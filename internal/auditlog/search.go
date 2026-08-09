// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart - Audit Log Search
//
// Provides search functionality for audit logs with filtering
// by date, severity, category, and pattern matching.

package auditlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/platform"
)

// SearchQuery defines search parameters for audit log queries
type SearchQuery struct {
	// Pattern to search for in all fields (case-insensitive)
	Pattern string
	// Filter by date range
	From time.Time
	To   time.Time
	// Filter by severity (empty = all)
	Severities []string
	// Filter by category (empty = all)
	Categories []string
	// Filter by direction (inbound/outbound)
	Direction string
	// Filter by host
	Host string
	// Only show blocked requests
	BlockedOnly bool
	// Pagination
	Offset int
	Limit  int
}

// SearchResult contains search results and metadata
type SearchResult struct {
	Entries    []Entry
	Total      int
	Offset     int
	Limit      int
	HasMore    bool
	SearchTime time.Duration
}

// Search searches audit log entries matching the query
func (l *Logger) Search(query SearchQuery) (*SearchResult, error) {
	startTime := time.Now()

	file, err := os.Open(l.path)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	result := &SearchResult{
		Offset: query.Offset,
		Limit:  query.Limit,
	}

	if query.Limit <= 0 {
		result.Limit = 100
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	matched := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			// Skip malformed lines
			continue
		}

		// Apply filters
		if !matchesQuery(entry, query) {
			continue
		}

		matched++
		result.Total = matched

		// Apply pagination
		if matched <= query.Offset {
			continue
		}

		if len(result.Entries) >= result.Limit {
			result.HasMore = true
			break
		}

		result.Entries = append(result.Entries, entry)
		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	result.SearchTime = time.Since(startTime)
	return result, nil
}

// matchesQuery checks if an entry matches the search query
func matchesQuery(entry Entry, query SearchQuery) bool {
	// Blocked filter
	if query.BlockedOnly && !entry.Blocked {
		return false
	}

	// Direction filter
	if query.Direction != "" && !strings.EqualFold(entry.Direction, query.Direction) {
		return false
	}

	// Host filter
	if query.Host != "" && !strings.Contains(strings.ToLower(entry.Host), strings.ToLower(query.Host)) {
		return false
	}

	// Date range filter
	if !query.From.IsZero() && entry.Timestamp.Before(query.From) {
		return false
	}
	if !query.To.IsZero() && entry.Timestamp.After(query.To) {
		return false
	}

	// Severity filter
	if len(query.Severities) > 0 {
		found := false
		for _, sev := range entry.Severities {
			for _, qsev := range query.Severities {
				if strings.EqualFold(sev, qsev) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// Category filter
	if len(query.Categories) > 0 {
		found := false
		for _, cat := range entry.Categories {
			for _, qcat := range query.Categories {
				if strings.EqualFold(cat, qcat) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// Pattern search (case-insensitive, searches all fields)
	if query.Pattern != "" {
		pattern := strings.ToLower(query.Pattern)
		
		// Search in string fields
		if strings.Contains(strings.ToLower(entry.Direction), pattern) {
			return true
		}
		if strings.Contains(strings.ToLower(entry.Host), pattern) {
			return true
		}
		if strings.Contains(strings.ToLower(entry.Path), pattern) {
			return true
		}

		// Search in slices
		for _, cat := range entry.Categories {
			if strings.Contains(strings.ToLower(cat), pattern) {
				return true
			}
		}
		for _, sev := range entry.Severities {
			if strings.Contains(strings.ToLower(sev), pattern) {
				return true
			}
		}
		for _, rule := range entry.Rules {
			if strings.Contains(strings.ToLower(rule), pattern) {
				return true
			}
		}
		for _, pii := range entry.PIICategories {
			if strings.Contains(strings.ToLower(pii), pattern) {
				return true
			}
		}
		for _, secret := range entry.SecretTypes {
			if strings.Contains(strings.ToLower(secret), pattern) {
				return true
			}
		}

		// No match found
		return false
	}

	return true
}

// SearchFile searches an audit log file by path (convenience function)
func SearchFile(logPath string, query SearchQuery) (*SearchResult, error) {
	// Create a temporary logger for searching
	logger := &Logger{path: logPath}
	return logger.Search(query)
}

// GetLogPath returns the default audit log path
func GetLogPath() string {
	dir := platform.DataDir()
	return filepath.Join(dir, "audit.log")
}

// FormatTime parses a time string in various formats
func FormatTime(s string) (time.Time, error) {
	// Try common formats
	formats := []string{
		"2006-01-02",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
		time.RFC3339,
		time.RFC3339Nano,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time: %s", s)
}
