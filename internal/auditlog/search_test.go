// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Audit Log Search Tests
// =========================================================================
//
// Comprehensive tests for search.go and defaultAuditLogPath() in encryption.go.
// Covers Search, matchesQuery, SearchFile, GetLogPath, FormatTime, and
// defaultAuditLogPath.
// =========================================================================

package auditlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeEntriesToFile writes the given entries as JSONL to the specified path.
func writeEntriesToFile(t *testing.T, path string, entries []Entry) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer f.Close()
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal entry: %v", err)
		}
		line = append(line, '\n')
		if _, err := f.Write(line); err != nil {
			t.Fatalf("write line: %v", err)
		}
	}
}

// makeTestEntry returns a representative Entry used across search tests.
func makeTestEntry() Entry {
	return Entry{
		Timestamp:     time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
		Direction:     "request",
		Host:          "api.openai.com",
		Path:          "/v1/chat/completions",
		TotalDets:     3,
		Blocked:       true,
		PIICategories: []string{"ssn"},
		SecretTypes:   []string{"aws_key"},
		Categories:    []string{"pii", "secret"},
		Severities:    []string{"critical", "high"},
		Rules:         []string{"pii_ssn", "secret_aws_key"},
	}
}

// makeLoggerWithPath creates a Logger backed by a file at path (file is
// created so that Search can open it).
func makeLoggerWithPath(t *testing.T, path string) *Logger {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	return &Logger{
		file:    f,
		path:    path,
		maxSize: DefaultMaxSize,
		writer:  f,
		nowFunc: time.Now,
	}
}

// ---------------------------------------------------------------------------
// Logger.Search tests
// ---------------------------------------------------------------------------

func TestSearch_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	// Create an empty file
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	result, err := logger.Search(SearchQuery{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("expected Total=0, got %d", result.Total)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(result.Entries))
	}
}

func TestSearch_Pattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	e1 := makeTestEntry()
	e2 := makeTestEntry()
	e2.Host = "api.anthropic.com"
	e2.Path = "/v1/messages"
	writeEntriesToFile(t, path, []Entry{e1, e2})

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	// Search by pattern matching host
	result, err := logger.Search(SearchQuery{Pattern: "openai"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected Total=1, got %d", result.Total)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Entries))
	}
	if result.Entries[0].Host != "api.openai.com" {
		t.Errorf("expected host api.openai.com, got %s", result.Entries[0].Host)
	}

	// Pattern matching path
	result2, err := logger.Search(SearchQuery{Pattern: "messages"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result2.Total != 1 {
		t.Errorf("expected Total=1 for path pattern, got %d", result2.Total)
	}

	// Pattern matching category (case-insensitive)
	result3, err := logger.Search(SearchQuery{Pattern: "PII"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result3.Total != 2 {
		t.Errorf("expected Total=2 for category pattern, got %d", result3.Total)
	}
}

func TestSearch_Severity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	e1 := makeTestEntry()
	e1.Severities = []string{"critical"}
	e2 := makeTestEntry()
	e2.Severities = []string{"low"}
	writeEntriesToFile(t, path, []Entry{e1, e2})

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	// Single severity
	result, err := logger.Search(SearchQuery{Severities: []string{"critical"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected Total=1 for critical, got %d", result.Total)
	}

	// Multiple severities
	result2, err := logger.Search(SearchQuery{Severities: []string{"critical", "low"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result2.Total != 2 {
		t.Errorf("expected Total=2 for critical+low, got %d", result2.Total)
	}

	// No matching severity
	result3, err := logger.Search(SearchQuery{Severities: []string{"medium"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result3.Total != 0 {
		t.Errorf("expected Total=0 for medium, got %d", result3.Total)
	}
}

func TestSearch_Category(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	e1 := makeTestEntry()
	e1.Categories = []string{"pii"}
	e2 := makeTestEntry()
	e2.Categories = []string{"secret"}
	writeEntriesToFile(t, path, []Entry{e1, e2})

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	result, err := logger.Search(SearchQuery{Categories: []string{"pii"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected Total=1 for pii category, got %d", result.Total)
	}

	result2, err := logger.Search(SearchQuery{Categories: []string{"pii", "secret"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result2.Total != 2 {
		t.Errorf("expected Total=2 for pii+secret, got %d", result2.Total)
	}
}

func TestSearch_Direction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	e1 := makeTestEntry()
	e1.Direction = "request"
	e2 := makeTestEntry()
	e2.Direction = "response"
	writeEntriesToFile(t, path, []Entry{e1, e2})

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	// Direction filter (case-insensitive via EqualFold)
	result, err := logger.Search(SearchQuery{Direction: "REQUEST"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected Total=1 for direction request, got %d", result.Total)
	}
	if len(result.Entries) != 1 || result.Entries[0].Direction != "request" {
		t.Errorf("expected request entry, got %v", result.Entries)
	}
}

func TestSearch_Host(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	e1 := makeTestEntry()
	e1.Host = "api.openai.com"
	e2 := makeTestEntry()
	e2.Host = "api.anthropic.com"
	writeEntriesToFile(t, path, []Entry{e1, e2})

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	// Host filter (case-insensitive, contains)
	result, err := logger.Search(SearchQuery{Host: "OpenAI"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected Total=1 for host openai, got %d", result.Total)
	}

	// Partial host match
	result2, err := logger.Search(SearchQuery{Host: "anthropic"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result2.Total != 1 {
		t.Errorf("expected Total=1 for host anthropic, got %d", result2.Total)
	}
}

func TestSearch_BlockedOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	e1 := makeTestEntry()
	e1.Blocked = true
	e2 := makeTestEntry()
	e2.Blocked = false
	writeEntriesToFile(t, path, []Entry{e1, e2})

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	result, err := logger.Search(SearchQuery{BlockedOnly: true})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected Total=1 for blockedOnly, got %d", result.Total)
	}
	if len(result.Entries) != 1 || !result.Entries[0].Blocked {
		t.Error("expected blocked entry")
	}
}

func TestSearch_DateRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	e1 := makeTestEntry()
	e1.Timestamp = time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	e2 := makeTestEntry()
	e2.Timestamp = time.Date(2025, 6, 16, 12, 0, 0, 0, time.UTC)
	e3 := makeTestEntry()
	e3.Timestamp = time.Date(2025, 6, 17, 12, 0, 0, 0, time.UTC)
	writeEntriesToFile(t, path, []Entry{e1, e2, e3})

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	// From date filter
	from := time.Date(2025, 6, 16, 0, 0, 0, 0, time.UTC)
	result, err := logger.Search(SearchQuery{From: from})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected Total=2 for From=06-16, got %d", result.Total)
	}

	// To date filter
	to := time.Date(2025, 6, 16, 23, 59, 59, 0, time.UTC)
	result2, err := logger.Search(SearchQuery{To: to})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result2.Total != 2 {
		t.Errorf("expected Total=2 for To=06-16, got %d", result2.Total)
	}

	// Date range (From + To) — only e2
	result3, err := logger.Search(SearchQuery{
		From: time.Date(2025, 6, 16, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2025, 6, 16, 23, 59, 59, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result3.Total != 1 {
		t.Errorf("expected Total=1 for range 06-16, got %d", result3.Total)
	}
}

func TestSearch_Pagination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	var entries []Entry
	for i := 0; i < 5; i++ {
		e := makeTestEntry()
		e.Host = fmt.Sprintf("host%d.example.com", i)
		entries = append(entries, e)
	}
	writeEntriesToFile(t, path, entries)

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	// Offset only — skip first 2
	result, err := logger.Search(SearchQuery{Offset: 2, Limit: 100})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 5 {
		t.Errorf("expected Total=5, got %d", result.Total)
	}
	if len(result.Entries) != 3 {
		t.Errorf("expected 3 entries after offset=2, got %d", len(result.Entries))
	}
	if result.Offset != 2 {
		t.Errorf("expected Offset=2, got %d", result.Offset)
	}

	// Limit only — get first 3
	result2, err := logger.Search(SearchQuery{Offset: 0, Limit: 3})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(result2.Entries) != 3 {
		t.Errorf("expected 3 entries with limit=3, got %d", len(result2.Entries))
	}
	if !result2.HasMore {
		t.Error("expected HasMore=true with limit=3 and 5 total")
	}
	if result2.Limit != 3 {
		t.Errorf("expected Limit=3, got %d", result2.Limit)
	}

	// Offset + Limit — skip 1, get 2
	result3, err := logger.Search(SearchQuery{Offset: 1, Limit: 2})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(result3.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result3.Entries))
	}
	if !result3.HasMore {
		t.Error("expected HasMore=true")
	}
}

func TestSearch_DefaultLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Write 2 entries — fewer than default limit
	var entries []Entry
	for i := 0; i < 2; i++ {
		e := makeTestEntry()
		entries = append(entries, e)
	}
	writeEntriesToFile(t, path, entries)

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	// Limit <= 0 should default to 100
	result, err := logger.Search(SearchQuery{Limit: 0})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Limit != 100 {
		t.Errorf("expected default Limit=100, got %d", result.Limit)
	}
	if len(result.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result.Entries))
	}
	if result.HasMore {
		t.Error("expected HasMore=false")
	}
}

func TestSearch_NoMatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	e := makeTestEntry()
	writeEntriesToFile(t, path, []Entry{e})

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	// Pattern that doesn't match any field
	result, err := logger.Search(SearchQuery{Pattern: "nonexistent"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("expected Total=0, got %d", result.Total)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(result.Entries))
	}
}

func TestSearch_SearchTime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	e := makeTestEntry()
	writeEntriesToFile(t, path, []Entry{e})

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	result, err := logger.Search(SearchQuery{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.SearchTime < 0 {
		t.Error("expected non-negative SearchTime")
	}
}

func TestSearch_MalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Write a malformed line followed by a valid one
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	_, _ = f.Write([]byte("not json\n"))
	validLine, _ := json.Marshal(makeTestEntry())
	validLine = append(validLine, '\n')
	_, _ = f.Write(validLine)
	f.Close()

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	result, err := logger.Search(SearchQuery{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected Total=1 (malformed line skipped), got %d", result.Total)
	}
}

func TestSearch_NonExistentFile(t *testing.T) {
	logger := &Logger{path: "/nonexistent/path/audit.log"}
	_, err := logger.Search(SearchQuery{})
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestSearch_CombinedFilters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	e1 := makeTestEntry()
	e1.Direction = "request"
	e1.Blocked = true
	e1.Severities = []string{"critical"}
	e1.Categories = []string{"pii"}

	e2 := makeTestEntry()
	e2.Direction = "response"
	e2.Blocked = false
	e2.Severities = []string{"high"}
	e2.Categories = []string{"secret"}

	writeEntriesToFile(t, path, []Entry{e1, e2})

	logger := makeLoggerWithPath(t, path)
	defer logger.Close()

	// Combine direction + blockedOnly + severity
	result, err := logger.Search(SearchQuery{
		Direction:   "request",
		BlockedOnly: true,
		Severities:  []string{"critical"},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected Total=1 for combined filters, got %d", result.Total)
	}
}

// ---------------------------------------------------------------------------
// matchesQuery tests
// ---------------------------------------------------------------------------

func TestMatchesQuery_EmptyQuery(t *testing.T) {
	entry := makeTestEntry()
	if !matchesQuery(entry, SearchQuery{}) {
		t.Error("empty query should match all entries")
	}
}

func TestMatchesQuery_Pattern_Host(t *testing.T) {
	entry := makeTestEntry()
	// Case-insensitive pattern match in Host
	if !matchesQuery(entry, SearchQuery{Pattern: "OPENAI"}) {
		t.Error("expected pattern 'OPENAI' to match host 'api.openai.com'")
	}
}

func TestMatchesQuery_Pattern_Path(t *testing.T) {
	entry := makeTestEntry()
	if !matchesQuery(entry, SearchQuery{Pattern: "chat"}) {
		t.Error("expected pattern 'chat' to match path '/v1/chat/completions'")
	}
}

func TestMatchesQuery_Pattern_Direction(t *testing.T) {
	entry := makeTestEntry()
	if !matchesQuery(entry, SearchQuery{Pattern: "request"}) {
		t.Error("expected pattern 'request' to match direction")
	}
}

func TestMatchesQuery_Pattern_Category(t *testing.T) {
	entry := makeTestEntry()
	if !matchesQuery(entry, SearchQuery{Pattern: "pii"}) {
		t.Error("expected pattern 'pii' to match category")
	}
}

func TestMatchesQuery_Pattern_Severity(t *testing.T) {
	entry := makeTestEntry()
	if !matchesQuery(entry, SearchQuery{Pattern: "critical"}) {
		t.Error("expected pattern 'critical' to match severity")
	}
}

func TestMatchesQuery_Pattern_Rule(t *testing.T) {
	entry := makeTestEntry()
	if !matchesQuery(entry, SearchQuery{Pattern: "pii_ssn"}) {
		t.Error("expected pattern 'pii_ssn' to match rule")
	}
}

func TestMatchesQuery_Pattern_PIICategory(t *testing.T) {
	entry := makeTestEntry()
	if !matchesQuery(entry, SearchQuery{Pattern: "ssn"}) {
		t.Error("expected pattern 'ssn' to match PII category")
	}
}

func TestMatchesQuery_Pattern_SecretType(t *testing.T) {
	entry := makeTestEntry()
	if !matchesQuery(entry, SearchQuery{Pattern: "aws_key"}) {
		t.Error("expected pattern 'aws_key' to match secret type")
	}
}

func TestMatchesQuery_Pattern_NoMatch(t *testing.T) {
	entry := makeTestEntry()
	if matchesQuery(entry, SearchQuery{Pattern: "nonexistent"}) {
		t.Error("expected pattern 'nonexistent' to not match")
	}
}

func TestMatchesQuery_Severity_Single(t *testing.T) {
	entry := makeTestEntry()
	entry.Severities = []string{"critical", "high"}
	if !matchesQuery(entry, SearchQuery{Severities: []string{"critical"}}) {
		t.Error("expected severity 'critical' to match")
	}
}

func TestMatchesQuery_Severity_Multiple(t *testing.T) {
	entry := makeTestEntry()
	entry.Severities = []string{"high"}
	// Query has multiple severities, entry matches one
	if !matchesQuery(entry, SearchQuery{Severities: []string{"critical", "high"}}) {
		t.Error("expected entry with 'high' to match query [critical, high]")
	}
}

func TestMatchesQuery_Severity_NoMatch(t *testing.T) {
	entry := makeTestEntry()
	entry.Severities = []string{"low"}
	if matchesQuery(entry, SearchQuery{Severities: []string{"critical"}}) {
		t.Error("expected severity 'critical' to not match entry with 'low'")
	}
}

func TestMatchesQuery_Severity_CaseInsensitive(t *testing.T) {
	entry := makeTestEntry()
	entry.Severities = []string{"Critical"}
	if !matchesQuery(entry, SearchQuery{Severities: []string{"critical"}}) {
		t.Error("expected case-insensitive severity match")
	}
}

func TestMatchesQuery_Category_Match(t *testing.T) {
	entry := makeTestEntry()
	entry.Categories = []string{"pii", "secret"}
	if !matchesQuery(entry, SearchQuery{Categories: []string{"pii"}}) {
		t.Error("expected category 'pii' to match")
	}
}

func TestMatchesQuery_Category_NoMatch(t *testing.T) {
	entry := makeTestEntry()
	entry.Categories = []string{"pii"}
	if matchesQuery(entry, SearchQuery{Categories: []string{"secret"}}) {
		t.Error("expected category 'secret' to not match entry with 'pii'")
	}
}

func TestMatchesQuery_Category_CaseInsensitive(t *testing.T) {
	entry := makeTestEntry()
	entry.Categories = []string{"PII"}
	if !matchesQuery(entry, SearchQuery{Categories: []string{"pii"}}) {
		t.Error("expected case-insensitive category match")
	}
}

func TestMatchesQuery_Direction_Match(t *testing.T) {
	entry := makeTestEntry()
	entry.Direction = "request"
	if !matchesQuery(entry, SearchQuery{Direction: "request"}) {
		t.Error("expected direction 'request' to match")
	}
}

func TestMatchesQuery_Direction_CaseInsensitive(t *testing.T) {
	entry := makeTestEntry()
	entry.Direction = "Request"
	if !matchesQuery(entry, SearchQuery{Direction: "REQUEST"}) {
		t.Error("expected case-insensitive direction match")
	}
}

func TestMatchesQuery_Direction_NoMatch(t *testing.T) {
	entry := makeTestEntry()
	entry.Direction = "request"
	if matchesQuery(entry, SearchQuery{Direction: "response"}) {
		t.Error("expected direction 'response' to not match entry with 'request'")
	}
}

func TestMatchesQuery_Host_Match(t *testing.T) {
	entry := makeTestEntry()
	entry.Host = "api.openai.com"
	if !matchesQuery(entry, SearchQuery{Host: "openai"}) {
		t.Error("expected host 'openai' to match 'api.openai.com'")
	}
}

func TestMatchesQuery_Host_CaseInsensitive(t *testing.T) {
	entry := makeTestEntry()
	entry.Host = "API.OpenAI.com"
	if !matchesQuery(entry, SearchQuery{Host: "openai"}) {
		t.Error("expected case-insensitive host match")
	}
}

func TestMatchesQuery_Host_NoMatch(t *testing.T) {
	entry := makeTestEntry()
	entry.Host = "api.openai.com"
	if matchesQuery(entry, SearchQuery{Host: "anthropic"}) {
		t.Error("expected host 'anthropic' to not match 'api.openai.com'")
	}
}

func TestMatchesQuery_BlockedOnly_Blocked(t *testing.T) {
	entry := makeTestEntry()
	entry.Blocked = true
	if !matchesQuery(entry, SearchQuery{BlockedOnly: true}) {
		t.Error("expected blocked entry to match BlockedOnly=true")
	}
}

func TestMatchesQuery_BlockedOnly_NotBlocked(t *testing.T) {
	entry := makeTestEntry()
	entry.Blocked = false
	if matchesQuery(entry, SearchQuery{BlockedOnly: true}) {
		t.Error("expected non-blocked entry to not match BlockedOnly=true")
	}
}

func TestMatchesQuery_DateFrom_Before(t *testing.T) {
	entry := makeTestEntry()
	entry.Timestamp = time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	from := time.Date(2025, 6, 16, 0, 0, 0, 0, time.UTC)
	if matchesQuery(entry, SearchQuery{From: from}) {
		t.Error("expected entry before From to not match")
	}
}

func TestMatchesQuery_DateFrom_After(t *testing.T) {
	entry := makeTestEntry()
	entry.Timestamp = time.Date(2025, 6, 17, 12, 0, 0, 0, time.UTC)
	from := time.Date(2025, 6, 16, 0, 0, 0, 0, time.UTC)
	if !matchesQuery(entry, SearchQuery{From: from}) {
		t.Error("expected entry after From to match")
	}
}

func TestMatchesQuery_DateTo_After(t *testing.T) {
	entry := makeTestEntry()
	entry.Timestamp = time.Date(2025, 6, 17, 12, 0, 0, 0, time.UTC)
	to := time.Date(2025, 6, 16, 23, 59, 59, 0, time.UTC)
	if matchesQuery(entry, SearchQuery{To: to}) {
		t.Error("expected entry after To to not match")
	}
}

func TestMatchesQuery_DateTo_Before(t *testing.T) {
	entry := makeTestEntry()
	entry.Timestamp = time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	to := time.Date(2025, 6, 16, 23, 59, 59, 0, time.UTC)
	if !matchesQuery(entry, SearchQuery{To: to}) {
		t.Error("expected entry before To to match")
	}
}

func TestMatchesQuery_DateRange_Within(t *testing.T) {
	entry := makeTestEntry()
	entry.Timestamp = time.Date(2025, 6, 16, 6, 0, 0, 0, time.UTC)
	query := SearchQuery{
		From: time.Date(2025, 6, 16, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2025, 6, 16, 23, 59, 59, 0, time.UTC),
	}
	if !matchesQuery(entry, query) {
		t.Error("expected entry within range to match")
	}
}

func TestMatchesQuery_DateRange_Outside(t *testing.T) {
	entry := makeTestEntry()
	entry.Timestamp = time.Date(2025, 6, 17, 6, 0, 0, 0, time.UTC)
	query := SearchQuery{
		From: time.Date(2025, 6, 16, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2025, 6, 16, 23, 59, 59, 0, time.UTC),
	}
	if matchesQuery(entry, query) {
		t.Error("expected entry outside range to not match")
	}
}

func TestMatchesQuery_CombinedFilters(t *testing.T) {
	entry := makeTestEntry()
	entry.Direction = "request"
	entry.Blocked = true
	entry.Severities = []string{"critical"}
	entry.Categories = []string{"pii"}
	entry.Host = "api.openai.com"

	// All filters match
	query := SearchQuery{
		Direction:   "request",
		BlockedOnly: true,
		Severities:  []string{"critical"},
		Categories:  []string{"pii"},
		Host:        "openai",
	}
	if !matchesQuery(entry, query) {
		t.Error("expected all filters to match")
	}

	// One filter fails
	query.Direction = "response"
	if matchesQuery(entry, query) {
		t.Error("expected direction mismatch to fail combined query")
	}
}

func TestMatchesQuery_PatternWithOtherFilters(t *testing.T) {
	entry := makeTestEntry()
	entry.Direction = "request"
	entry.Host = "api.openai.com"
	entry.Severities = []string{"critical"}

	// Both pattern and severity match
	query := SearchQuery{
		Pattern:    "openai",
		Severities: []string{"critical"},
	}
	if !matchesQuery(entry, query) {
		t.Error("expected pattern+severity to match")
	}

	// Pattern matches but severity doesn't
	query.Severities = []string{"low"}
	if matchesQuery(entry, query) {
		t.Error("expected severity mismatch to fail even when pattern matches")
	}

	// Severity matches but pattern doesn't
	query.Severities = []string{"critical"}
	query.Pattern = "nonexistent"
	if matchesQuery(entry, query) {
		t.Error("expected pattern mismatch to fail even when severity matches")
	}
}

// ---------------------------------------------------------------------------
// SearchFile tests
// ---------------------------------------------------------------------------

func TestSearchFile_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// The default audit dir is within tmpDir — pass a non-existent file in it
	defaultPath := GetLogPath()
	defaultDir := filepath.Dir(defaultPath)
	nonExistent := filepath.Join(defaultDir, "missing.log")

	_, err := SearchFile(nonExistent, SearchQuery{})
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestSearchFile_WithMatches(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	defaultPath := GetLogPath()
	defaultDir := filepath.Dir(defaultPath)

	if err := os.MkdirAll(defaultDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logPath := filepath.Join(defaultDir, "test_search.log")
	e := makeTestEntry()
	writeEntriesToFile(t, logPath, []Entry{e})

	result, err := SearchFile(logPath, SearchQuery{Pattern: "openai"})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected Total=1, got %d", result.Total)
	}
	if len(result.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result.Entries))
	}
}

func TestSearchFile_NoMatches(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	defaultPath := GetLogPath()
	defaultDir := filepath.Dir(defaultPath)

	if err := os.MkdirAll(defaultDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logPath := filepath.Join(defaultDir, "test_no_match.log")
	e := makeTestEntry()
	writeEntriesToFile(t, logPath, []Entry{e})

	result, err := SearchFile(logPath, SearchQuery{Pattern: "nonexistent"})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("expected Total=0, got %d", result.Total)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(result.Entries))
	}
}

func TestSearchFile_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Path outside the audit log directory
	_, err := SearchFile("/etc/passwd", SearchQuery{})
	if err == nil {
		t.Fatal("expected error for path outside audit log directory")
	}
	if !strings.Contains(err.Error(), "outside audit log directory") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSearchFile_SubdirectoryAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	defaultPath := GetLogPath()
	defaultDir := filepath.Dir(defaultPath)

	subDir := filepath.Join(defaultDir, "archive")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logPath := filepath.Join(subDir, "archived.log")
	e := makeTestEntry()
	writeEntriesToFile(t, logPath, []Entry{e})

	result, err := SearchFile(logPath, SearchQuery{})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected Total=1, got %d", result.Total)
	}
}

// ---------------------------------------------------------------------------
// GetLogPath tests
// ---------------------------------------------------------------------------

func TestGetLogPath(t *testing.T) {
	path := GetLogPath()
	if path == "" {
		t.Fatal("expected non-empty log path")
	}
	if !strings.HasSuffix(path, "audit.log") {
		t.Errorf("expected path to end with 'audit.log', got %s", path)
	}
}

func TestGetLogPath_ContainsDir(t *testing.T) {
	path := GetLogPath()
	lowerPath := strings.ToLower(path)
	if !strings.Contains(lowerPath, "aegisgate") {
		t.Errorf("expected path to contain 'aegisgate', got %s", path)
	}
}

// ---------------------------------------------------------------------------
// FormatTime tests
// ---------------------------------------------------------------------------

func TestFormatTime_RFC3339(t *testing.T) {
	input := "2025-06-15T12:00:00Z"
	tt, err := FormatTime(input)
	if err != nil {
		t.Fatalf("FormatTime: %v", err)
	}
	if tt.Year() != 2025 {
		t.Errorf("expected year 2025, got %d", tt.Year())
	}
	if tt.Month() != time.June {
		t.Errorf("expected month June, got %s", tt.Month())
	}
	if tt.Day() != 15 {
		t.Errorf("expected day 15, got %d", tt.Day())
	}
}

func TestFormatTime_RFC3339WithOffset(t *testing.T) {
	input := "2025-06-15T12:00:00-07:00"
	tt, err := FormatTime(input)
	if err != nil {
		t.Fatalf("FormatTime: %v", err)
	}
	if tt.Year() != 2025 {
		t.Errorf("expected year 2025, got %d", tt.Year())
	}
}

func TestFormatTime_RFC3339Nano(t *testing.T) {
	input := "2025-06-15T12:00:00.123456789Z"
	tt, err := FormatTime(input)
	if err != nil {
		t.Fatalf("FormatTime: %v", err)
	}
	if tt.Year() != 2025 {
		t.Errorf("expected year 2025, got %d", tt.Year())
	}
}

func TestFormatTime_DateOnly(t *testing.T) {
	input := "2025-06-15"
	tt, err := FormatTime(input)
	if err != nil {
		t.Fatalf("FormatTime: %v", err)
	}
	if tt.Year() != 2025 || tt.Month() != time.June || tt.Day() != 15 {
		t.Errorf("expected 2025-06-15, got %v", tt)
	}
}

func TestFormatTime_DateTimeNoZone(t *testing.T) {
	input := "2025-06-15T12:00:00"
	tt, err := FormatTime(input)
	if err != nil {
		t.Fatalf("FormatTime: %v", err)
	}
	if tt.Year() != 2025 || tt.Hour() != 12 {
		t.Errorf("expected 2025-06-15T12:00:00, got %v", tt)
	}
}

func TestFormatTime_SpaceSeparator(t *testing.T) {
	input := "2025-06-15 12:00:00"
	tt, err := FormatTime(input)
	if err != nil {
		t.Fatalf("FormatTime: %v", err)
	}
	if tt.Year() != 2025 || tt.Hour() != 12 {
		t.Errorf("expected 2025-06-15 12:00:00, got %v", tt)
	}
}

func TestFormatTime_Invalid(t *testing.T) {
	_, err := FormatTime("not-a-date")
	if err == nil {
		t.Fatal("expected error for invalid time string")
	}
	if !strings.Contains(err.Error(), "unable to parse time") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestFormatTime_EmptyString(t *testing.T) {
	_, err := FormatTime("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestFormatTime_Garbage(t *testing.T) {
	_, err := FormatTime("abc123!@#")
	if err == nil {
		t.Fatal("expected error for garbage string")
	}
}

// ---------------------------------------------------------------------------
// defaultAuditLogPath tests (encryption.go)
// ---------------------------------------------------------------------------

func TestDefaultAuditLogPath(t *testing.T) {
	path := defaultAuditLogPath()
	if path == "" {
		t.Fatal("expected non-empty path from defaultAuditLogPath")
	}
	lower := strings.ToLower(path)
	if !strings.Contains(lower, "aegisgate") && !strings.Contains(lower, "rampart") && !strings.Contains(lower, "audit") {
		t.Errorf("expected path to contain 'aegisgate', 'rampart', or 'audit'; got %s", path)
	}
}

func TestDefaultAuditLogPath_EndsWithAuditLog(t *testing.T) {
	path := defaultAuditLogPath()
	if !strings.HasSuffix(path, "audit.log") {
		t.Errorf("expected path to end with 'audit.log', got %s", path)
	}
}
