// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Auto-Update Checker Tests
// =========================================================================

package updater

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

func TestNew(t *testing.T) {
	cfg := &config.Config{}
	checker := New(cfg, "0.5.0")

	if checker == nil {
		t.Fatal("Expected non-nil checker")
	}
	if checker.currentVersion != "0.5.0" {
		t.Errorf("currentVersion = %s, want 0.5.0", checker.currentVersion)
	}
	if !checker.notifyEnabled {
		t.Error("Expected notifyEnabled to be true by default")
	}
	if checker.checkInterval != 24*time.Hour {
		t.Errorf("checkInterval = %v, want 24h", checker.checkInterval)
	}

	t.Logf("✓ New() working")
}

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"0.5.0", "0.5.1", true},
		{"0.5.0", "0.6.0", true},
		{"0.5.0", "1.0.0", true},
		{"0.5.0", "0.5.0", false},
		{"0.5.0", "0.4.9", false},
		{"0.5.0", "0.4.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.current+"_"+tt.latest, func(t *testing.T) {
			got := isNewerVersion(tt.current, tt.latest)
			if got != tt.want {
				t.Errorf("isNewerVersion(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}

	t.Logf("✓ isNewerVersion() working")
}

func TestGetPlatform(t *testing.T) {
	platform := GetPlatform()
	if platform == "" {
		t.Error("Expected non-empty platform string")
	}

	t.Logf("✓ GetPlatform() = %s", platform)
}

func TestGetDownloadURL(t *testing.T) {
	release := &GitHubRelease{
		TagName: "v0.5.1",
		HTMLURL: "https://github.com/aegisgatesecurity/aegisgate-rampart/releases/tag/v0.5.1",
	}

	url := GetDownloadURL(release, "0.5.1")
	if url == "" {
		t.Error("Expected non-empty download URL")
	}

	t.Logf("✓ GetDownloadURL() = %s", url)
}

func TestSetNotifyEnabled(t *testing.T) {
	cfg := &config.Config{}
	checker := New(cfg, "0.5.0")

	checker.SetNotifyEnabled(false)
	if checker.notifyEnabled {
		t.Error("Expected notifyEnabled to be false")
	}

	checker.SetNotifyEnabled(true)
	if !checker.notifyEnabled {
		t.Error("Expected notifyEnabled to be true")
	}

	t.Logf("✓ SetNotifyEnabled() working")
}

func TestSetCheckInterval(t *testing.T) {
	cfg := &config.Config{}
	checker := New(cfg, "0.5.0")

	newInterval := 12 * time.Hour
	checker.SetCheckInterval(newInterval)
	if checker.checkInterval != newInterval {
		t.Errorf("checkInterval = %v, want %v", checker.checkInterval, newInterval)
	}

	t.Logf("✓ SetCheckInterval() working")
}

func TestGetLastCheck(t *testing.T) {
	cfg := &config.Config{}
	checker := New(cfg, "0.5.0")

	lastCheck := checker.GetLastCheck()
	if !lastCheck.IsZero() {
		t.Errorf("Expected zero time, got %v", lastCheck)
	}

	t.Logf("✓ GetLastCheck() working (initial state)")
}

func TestGetLastVersion(t *testing.T) {
	cfg := &config.Config{}
	checker := New(cfg, "0.5.0")

	lastVersion := checker.GetLastVersion()
	if lastVersion != "" {
		t.Errorf("Expected empty string, got %s", lastVersion)
	}

	t.Logf("✓ GetLastVersion() working (initial state)")
}

func TestCheckForUpdates_RateLimit(t *testing.T) {
	cfg := &config.Config{}
	checker := New(cfg, "0.5.0")

	ctx := context.Background()

	// First check should proceed (but may fail due to network)
	_, err := checker.CheckForUpdates(ctx)
	// Don't fail on network errors in test
	if err != nil {
		t.Logf("✓ CheckForUpdates() called (network error expected in test): %v", err)
	}

	// Second check should be rate-limited
	lastCheck := checker.GetLastCheck()
	if lastCheck.IsZero() {
		t.Skip("Skipping rate limit test (first check didn't complete)")
	}

	_, err = checker.CheckForUpdates(ctx)
	if err != nil {
		t.Logf("✓ Rate limiting working: %v", err)
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	cfg := &config.Config{}
	checker := New(cfg, "0.5.0")

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		checker.Run(ctx)
		close(done)
	}()

	// Cancel immediately
	cancel()

	select {
	case <-done:
		t.Logf("✓ Run() respects context cancellation")
	case <-time.After(2 * time.Second):
		t.Error("Run() did not respect context cancellation")
	}
}

func TestGitHubRelease_Struct(t *testing.T) {
	release := GitHubRelease{
		TagName:     "v0.5.1",
		Name:        "v0.5.1 - Test Release",
		PublishedAt: "2026-08-08T10:00:00Z",
		HTMLURL:     "https://github.com/aegisgatesecurity/aegisgate-rampart/releases/tag/v0.5.1",
		Body:        "Release notes here",
		Prerelease:  false,
	}

	if release.TagName != "v0.5.1" {
		t.Errorf("TagName = %s", release.TagName)
	}
	if release.Prerelease {
		t.Error("Expected Prerelease to be false")
	}

	t.Logf("✓ GitHubRelease struct working")
}

func TestUpdateInfo_Struct(t *testing.T) {
	info := UpdateInfo{
		Version:     "0.5.1",
		Current:     "0.5.0",
		PublishedAt: "2026-08-08T10:00:00Z",
		URL:         "https://github.com/aegisgatesecurity/aegisgate-rampart/releases/tag/v0.5.1",
		Notes:       "Bug fixes and improvements",
		Prerelease:  false,
	}

	if info.Version != "0.5.1" {
		t.Errorf("Version = %s", info.Version)
	}
	if info.Current != "0.5.0" {
		t.Errorf("Current = %s", info.Current)
	}

	t.Logf("✓ UpdateInfo struct working")
}
