// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart - Audit Log Search CLI Commands

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/auditlog"
)

func runAuditCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("audit subcommand required: search, tail, stats")
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "search":
		return runAuditSearch(subargs)
	case "tail":
		return runAuditTail(subargs)
	case "stats":
		return runAuditStats(subargs)
	default:
		return fmt.Errorf("unknown audit subcommand: %s", subcmd)
	}
}

func runAuditSearch(args []string) error {
	fs := flag.NewFlagSet("audit search", flag.ExitOnError)
	pattern := fs.String("q", "", "Search pattern (case-insensitive)")
	fromStr := fs.String("from", "", "Start date (YYYY-MM-DD)")
	toStr := fs.String("to", "", "End date (YYYY-MM-DD)")
	severities := fs.String("severity", "", "Filter by severity (comma-separated)")
	categories := fs.String("category", "", "Filter by category (comma-separated)")
	direction := fs.String("direction", "", "Filter by direction (inbound/outbound)")
	host := fs.String("host", "", "Filter by host")
	blockedOnly := fs.Bool("blocked", false, "Only show blocked requests")
	offset := fs.Int("offset", 0, "Result offset for pagination")
	limit := fs.Int("limit", 100, "Maximum results to return")
	format := fs.String("format", "table", "Output format: table, json, raw")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Parse dates
	var fromTime, toTime time.Time
	var err error
	
	if *fromStr != "" {
		fromTime, err = auditlog.FormatTime(*fromStr)
		if err != nil {
			return fmt.Errorf("invalid from date: %w", err)
		}
		// Set to start of day
		fromTime = time.Date(fromTime.Year(), fromTime.Month(), fromTime.Day(), 0, 0, 0, 0, fromTime.Location())
	}
	
	if *toStr != "" {
		toTime, err = auditlog.FormatTime(*toStr)
		if err != nil {
			return fmt.Errorf("invalid to date: %w", err)
		}
		// Set to end of day
		toTime = time.Date(toTime.Year(), toTime.Month(), toTime.Day(), 23, 59, 59, 0, toTime.Location())
	} else {
		// Default to now
		toTime = time.Now()
	}

	// Parse severities and categories
	var sevList, catList []string
	if *severities != "" {
		sevList = splitString(*severities, ",")
	}
	if *categories != "" {
		catList = splitString(*categories, ",")
	}

	// Build query
	query := auditlog.SearchQuery{
		Pattern:    *pattern,
		From:       fromTime,
		To:         toTime,
		Severities: sevList,
		Categories: catList,
		Direction:  *direction,
		Host:       *host,
		BlockedOnly: *blockedOnly,
		Offset:     *offset,
		Limit:      *limit,
	}

	// Get log path
	logPath := filepath.Join(getConfigDir(), "..", "aegisgate-rampart", "audit.log")
	
	// Try default location first
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		logPath = auditlog.GetLogPath()
	}

	// Search
	result, err := auditlog.SearchFile(logPath, query)
	if err != nil {
		return fmt.Errorf("search audit log: %w", err)
	}

	// Output results
	switch *format {
	case "json":
		return outputJSON(result)
	case "raw":
		return outputRaw(result)
	default:
		return outputTable(result, logPath)
	}
}

func outputTable(result *auditlog.SearchResult, logPath string) error {
	if len(result.Entries) == 0 {
		fmt.Printf("No matching entries found\n")
		fmt.Printf("Total matches: %d (search took %v)\n", result.Total, result.SearchTime)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tDIRECTION\tHOST\tBLOCKED\tSEVERITY\tCATEGORIES")

	for _, entry := range result.Entries {
		blocked := "✓"
		if !entry.Blocked {
			blocked = " "
		}

		severity := "-"
		if len(entry.Severities) > 0 {
			severity = entry.Severities[0]
		}

		categories := "-"
		if len(entry.Categories) > 0 {
			categories = entry.Categories[0]
			if len(entry.Categories) > 1 {
				categories += fmt.Sprintf(" (+%d)", len(entry.Categories)-1)
			}
		}

		timestamp := entry.Timestamp.Format("2006-01-02 15:04:05")

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			timestamp, entry.Direction, truncateString(entry.Host, 20),
			blocked, severity, categories)
	}

	w.Flush()

	fmt.Printf("\nShowing %d of %d matches (search took %v)\n",
		len(result.Entries), result.Total, result.SearchTime)

	if result.HasMore {
		fmt.Printf("Use --offset %d to see more results\n", result.Offset+result.Limit)
	}

	return nil
}

func outputJSON(result *auditlog.SearchResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func outputRaw(result *auditlog.SearchResult) error {
	for _, entry := range result.Entries {
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	}
	return nil
}

func runAuditTail(args []string) error {
	fs := flag.NewFlagSet("audit tail", flag.ExitOnError)
	lines := fs.Int("n", 20, "Number of lines to show")
	follow := fs.Bool("f", false, "Follow log output (like tail -f)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	logPath := auditlog.GetLogPath()

	// Read last N lines
	file, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	var allLines []string
	scanner := bufioScanner(file)
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}

	// Show last N lines
	start := len(allLines) - *lines
	if start < 0 {
		start = 0
	}

	for _, line := range allLines[start:] {
		fmt.Println(line)
	}

	if *follow {
		// TODO: Implement follow mode
		fmt.Println("\nFollow mode not yet implemented")
	}

	return nil
}

func runAuditStats(args []string) error {
	logPath := auditlog.GetLogPath()

	file, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	total := 0
	blocked := 0
	byCategory := make(map[string]int)
	bySeverity := make(map[string]int)
	byHost := make(map[string]int)

	scanner := bufioScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry auditlog.Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		total++
		if entry.Blocked {
			blocked++
		}

		for _, cat := range entry.Categories {
			byCategory[cat]++
		}

		for _, sev := range entry.Severities {
			bySeverity[sev]++
		}

		byHost[entry.Host]++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}

	fmt.Printf("Audit Log Statistics\n")
	fmt.Printf("====================\n\n")
	fmt.Printf("Total Entries: %d\n", total)
	fmt.Printf("Blocked: %d (%.1f%%)\n", blocked, float64(blocked)/float64(total)*100)
	fmt.Printf("Allowed: %d (%.1f%%)\n\n", total-blocked, float64(total-blocked)/float64(total)*100)

	fmt.Printf("By Category:\n")
	for cat, count := range byCategory {
		fmt.Printf("  %-30s %d\n", cat, count)
	}

	fmt.Printf("\nBy Severity:\n")
	for sev, count := range bySeverity {
		fmt.Printf("  %-30s %d\n", sev, count)
	}

	fmt.Printf("\nBy Host (top 10):\n")
	// Sort and show top 10 hosts
	// (simplified for now)
	count := 0
	for host, c := range byHost {
		if count >= 10 {
			break
		}
		fmt.Printf("  %-30s %d\n", host, c)
		count++
	}

	return nil
}

// Helper functions
func splitString(s, sep string) []string {
	if s == "" {
		return nil
	}
	return stringsSplit(s, sep)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// Simple scanner wrapper (avoiding import issues)
func bufioScanner(f *os.File) *scannerWrapper {
	return &scannerWrapper{
		scanner: bufio.NewScanner(f),
	}
}

type scannerWrapper struct {
	scanner *bufio.Scanner
}

func (s *scannerWrapper) Scan() bool {
	return s.scanner.Scan()
}

func (s *scannerWrapper) Text() string {
	return s.scanner.Text()
}

func (s *scannerWrapper) Bytes() []byte {
	return s.scanner.Bytes()
}

func (s *scannerWrapper) Err() error {
	return s.scanner.Err()
}

// String functions (avoiding import issues)
func stringsSplit(s, sep string) []string {
	result := []string{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i = start - 1
		}
	}
	return result
}
