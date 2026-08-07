// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Desktop Notifications
// =========================================================================
//
// Cross-platform desktop notification support:
//   - Linux:   notify-send (libnotify)
//   - macOS:   osascript (AppleScript)
//   - Windows: beeep (Win32 toast)
//
// Air-gap ready: notifications are local only, no network required.
//
// =========================================================================

package notify

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	beeep "github.com/gen2brain/beeep"
)

//go:embed rampart-shield-64.png
var defaultIconData []byte

// Notification represents a desktop notification.
type Notification struct {
	Title   string
	Body    string
	Icon    string   // Path to icon file (optional)
	Actions []string // Actions for Linux notify-send (optional)
}

// Notifier sends desktop notifications.
type Notifier struct {
	enabled  bool
	icon     string // Explicitly provided icon path (highest priority)
	iconPath string // Resolved icon file path (written from embedded data)
}

// New creates a new desktop notifier.
// iconPath is the path to the tray icon for notifications.
// If iconPath is empty, the embedded default icon is used.
func New(iconPath string) *Notifier {
	n := &Notifier{
		enabled: true,
		icon:    iconPath,
	}
	// Resolve icon: if no path provided, use embedded default
	if iconPath == "" {
		n.iconPath = n.ensureDefaultIcon()
	} else {
		n.iconPath = iconPath
	}
	return n
}

// ensureDefaultIcon writes the embedded icon to a temp file and returns its path.
func (n *Notifier) ensureDefaultIcon() string {
	iconDir := filepath.Join(os.TempDir(), "aegisgate-rampart")
	iconFile := filepath.Join(iconDir, "rampart-shield-64.png")

	if _, err := os.Stat(iconFile); err == nil {
		return iconFile
	}

	if err := os.MkdirAll(iconDir, 0755); err != nil {
		return ""
	}
	if err := os.WriteFile(iconFile, defaultIconData, 0644); err != nil {
		return ""
	}
	return iconFile
}

// resolveIcon picks the best available icon:
// 1. Per-notification icon (if the file exists on disk)
// 2. Notifier default icon (if the file exists on disk)
// 3. Embedded default icon (written to disk)
// 4. Empty string (no icon — let the OS decide)
func (n *Notifier) resolveIcon(notifIcon string) string {
	// Prefer per-notification icon if it resolves to a real file
	if notifIcon != "" {
		if abs, err := filepath.Abs(notifIcon); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	// Fall back to notifier default icon
	if n.iconPath != "" {
		if abs, err := filepath.Abs(n.iconPath); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	// Last resort: ensure embedded default is written to disk
	return n.ensureDefaultIcon()
}

// Send delivers a desktop notification.
func (n *Notifier) Send(notif Notification) error {
	if !n.enabled {
		return nil
	}

	icon := n.resolveIcon(notif.Icon)

	switch runtime.GOOS {
	case "linux":
		return n.notifyLinux(notif, icon)
	case "darwin":
		return n.notifyDarwin(notif)
	case "windows":
		return n.notifyWindows(notif, icon)
	default:
		// Fallback: try beeep
		return beeep.Notify(notif.Title, notif.Body, icon)
	}
}

// SendDetection sends a notification for a detection event.
func (n *Notifier) SendDetection(host string, totalDetections int, categories []string) error {
	title := "⚠️ AegisGate Rampart"
	body := fmt.Sprintf("%d threat(s) detected on %s", totalDetections, host)
	if len(categories) > 0 {
		body += fmt.Sprintf("\nCategories: %s", strings.Join(categories, ", "))
	}
	return n.Send(Notification{
		Title: title,
		Body:  body,
	})
}

// SendBlocked sends a notification for a blocked request.
func (n *Notifier) SendBlocked(host string, reason string) error {
	return n.Send(Notification{
		Title: "🚫 AegisGate Rampart — Request Blocked",
		Body:  fmt.Sprintf("Request to %s blocked: %s", host, reason),
	})
}

// SendStartup sends a notification that Rampart has started.
func (n *Notifier) SendStartup(port int, targets int) error {
	return n.Send(Notification{
		Title: "🛡️ AegisGate Rampart — Active",
		Body:  fmt.Sprintf("Monitoring %d AI API endpoints on port %d", targets, port),
	})
}

// Enable enables notifications.
func (n *Notifier) Enable() { n.enabled = true }

// Disable disables notifications.
func (n *Notifier) Disable() { n.enabled = false }

// IsEnabled returns whether notifications are enabled.
func (n *Notifier) IsEnabled() bool { return n.enabled }

// notifyLinux uses notify-send (libnotify) for Linux desktop notifications.
func (n *Notifier) notifyLinux(notif Notification, icon string) error {
	args := []string{}

	if icon != "" {
		args = append(args, "-i", icon)
	}

	args = append(args, notif.Title, notif.Body)

	cmd := exec.Command("notify-send", args...)
	return cmd.Run()
}

// notifyDarwin uses osascript for macOS desktop notifications.
func (n *Notifier) notifyDarwin(notif Notification) error {
	// Escape double quotes in the body
	body := strings.ReplaceAll(notif.Body, `"`, `\"`)
	title := strings.ReplaceAll(notif.Title, `"`, `\"`)

	script := fmt.Sprintf(`display notification "%s" with title "%s"`, body, title)
	cmd := exec.Command("osascript", "-e", script)
	return cmd.Run()
}

// notifyWindows uses beeep for Windows toast notifications.
func (n *Notifier) notifyWindows(notif Notification, icon string) error {
	return beeep.Notify(notif.Title, notif.Body, icon)
}
