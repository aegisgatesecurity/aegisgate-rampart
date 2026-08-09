// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Auto-Update Checker
// =========================================================================
//
// Checks GitHub Releases for new versions and notifies users.
// Runs periodically in daemon mode.
//
// =========================================================================

package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/notify"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
)

// GitHubRelease represents a GitHub release response
type GitHubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
	Prerelease  bool   `json:"prerelease"`
}

// Checker checks for new releases
type Checker struct {
	cfg           *config.Config
	currentVersion string
	notifyEnabled  bool
	checkInterval  time.Duration
	lastCheck      time.Time
	lastVersion    string
}

// New creates a new update checker
func New(cfg *config.Config, version string) *Checker {
	return &Checker{
		cfg:            cfg,
		currentVersion: version,
		notifyEnabled:  true, // Enabled by default
		checkInterval:  24 * time.Hour,
	}
}

// CheckForUpdates checks GitHub for new releases
func (c *Checker) CheckForUpdates(ctx context.Context) (*UpdateInfo, error) {
	// Rate limit checks
	if time.Since(c.lastCheck) < c.checkInterval {
		return nil, nil // Too soon
	}

	// Get latest release from GitHub
	release, err := c.getLatestRelease(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}

	c.lastCheck = time.Now()

	// Parse version
	latestVersion := strings.TrimPrefix(release.TagName, "v")
	if !isNewerVersion(c.currentVersion, latestVersion) {
		return nil, nil // Already up to date
	}

	c.lastVersion = latestVersion

	// Create update info
	info := &UpdateInfo{
		Version:     latestVersion,
		Current:     c.currentVersion,
		PublishedAt: release.PublishedAt,
		URL:         release.HTMLURL,
		Notes:       release.Body,
		Prerelease:  release.Prerelease,
	}

	// Send notification if enabled
	if c.notifyEnabled {
		c.sendNotification(info)
	}

	return info, nil
}

// getLatestRelease fetches the latest release from GitHub
func (c *Checker) getLatestRelease(ctx context.Context) (*GitHubRelease, error) {
	url := "https://api.github.com/repos/aegisgatesecurity/aegisgate-rampart/releases/latest"
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// GitHub API requires User-Agent
	req.Header.Set("User-Agent", "AegisGate-Rampart/"+c.currentVersion)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var release GitHubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, err
	}

	return &release, nil
}

// isNewerVersion checks if latest is newer than current
func isNewerVersion(current, latest string) bool {
	// Simple semver comparison
	// TODO: Use proper semver library for production
	return latest > current
}

// sendNotification sends a system notification about the update
func (c *Checker) sendNotification(info *UpdateInfo) {
	title := "AegisGate Rampart Update Available"
	message := fmt.Sprintf("Version %s is available (you have %s)\nClick to download", info.Version, info.Current)
	
	// Use system notification
	n := notify.New("")
	n.Send(notify.Notification{
		Title:   title,
		Body:    message,
		Actions: []string{"Download: " + info.URL},
	})
}

// UpdateInfo contains information about an available update
type UpdateInfo struct {
	Version     string `json:"version"`
	Current     string `json:"current"`
	PublishedAt string `json:"published_at"`
	URL         string `json:"url"`
	Notes       string `json:"notes"`
	Prerelease  bool   `json:"prerelease"`
}

// Run starts the periodic update checker
func (c *Checker) Run(ctx context.Context) {
	ticker := time.NewTicker(c.checkInterval)
	defer ticker.Stop()

	// Check immediately on start
	c.CheckForUpdates(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.CheckForUpdates(ctx)
		}
	}
}

// SetNotifyEnabled enables or disables notifications
func (c *Checker) SetNotifyEnabled(enabled bool) {
	c.notifyEnabled = enabled
}

// SetCheckInterval sets the check interval
func (c *Checker) SetCheckInterval(d time.Duration) {
	c.checkInterval = d
}

// GetLastCheck returns the last check time
func (c *Checker) GetLastCheck() time.Time {
	return c.lastCheck
}

// GetLastVersion returns the last found version
func (c *Checker) GetLastVersion() string {
	return c.lastVersion
}

// GetPlatform returns the current platform string for download URLs
func GetPlatform() string {
	os := runtime.GOOS
	arch := runtime.GOARCH
	return fmt.Sprintf("%s-%s", os, arch)
}

// GetDownloadURL returns the download URL for the current platform
func GetDownloadURL(release *GitHubRelease, version string) string {
	platform := GetPlatform()
	baseURL := "https://github.com/aegisgatesecurity/aegisgate-rampart/releases/download"
	
	// Map platform to asset name
	assetName := fmt.Sprintf("rampart-%s", platform)
	if platform == "windows-amd64" {
		assetName += ".exe"
	}
	
	return fmt.Sprintf("%s/v%s/%s", baseURL, version, assetName)
}
