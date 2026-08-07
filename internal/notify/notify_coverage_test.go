// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestNew_EnsureDefaultIcon verifies that New() creates the default icon file.
func TestNew_EnsureDefaultIcon(t *testing.T) {
	// Use a temp dir to ensure icon is freshly created
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	n := New("")
	if n == nil {
		t.Fatal("New returned nil")
	}

	// The icon path should have been set
	iconPath := n.ensureDefaultIcon()
	if iconPath == "" {
		t.Error("ensureDefaultIcon should return a path")
	}

	// Verify the icon file exists
	if _, err := os.Stat(iconPath); err != nil {
		t.Errorf("Icon file should exist at %s: %v", iconPath, err)
	}

	// Calling again should return same path (idempotent)
	iconPath2 := n.ensureDefaultIcon()
	if iconPath2 != iconPath {
		t.Errorf("ensureDefaultIcon should be idempotent: got %s, want %s", iconPath2, iconPath)
	}
}

// TestNew_WithExplicitIconPath verifies that New() uses the provided icon path.
func TestNew_WithExplicitIconPath(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "custom-icon.png")
	if err := os.WriteFile(tmpFile, []byte("fake png data"), 0644); err != nil {
		t.Fatal(err)
	}

	n := New(tmpFile)
	if n.iconPath != tmpFile {
		t.Errorf("iconPath = %s, want %s", n.iconPath, tmpFile)
	}
	if n.icon != tmpFile {
		t.Errorf("icon = %s, want %s", n.icon, tmpFile)
	}
}

// TestResolveIcon_PerNotificationIcon verifies resolveIcon with a per-notification icon.
func TestResolveIcon_PerNotificationIcon(t *testing.T) {
	// Create a temporary icon file
	tmpDir := t.TempDir()
	iconFile := filepath.Join(tmpDir, "notif-icon.png")
	if err := os.WriteFile(iconFile, []byte("fake png"), 0644); err != nil {
		t.Fatal(err)
	}

	n := New("")
	resolved := n.resolveIcon(iconFile)
	if resolved == "" {
		t.Error("resolveIcon should return a path when given a valid icon file")
	}

	// The resolved path should be the absolute path of the icon file
	abs, _ := filepath.Abs(iconFile)
	if resolved != abs {
		t.Errorf("resolveIcon should return the absolute path of the per-notification icon: got %s, want %s", resolved, abs)
	}
}

// TestResolveIcon_NonExistentPerNotificationIcon verifies fallback behavior.
func TestResolveIcon_NonExistentPerNotificationIcon(t *testing.T) {
	n := New("")
	resolved := n.resolveIcon("/nonexistent/path/icon.png")
	// Should fall back to notifier default icon or embedded icon
	if resolved == "" && n.iconPath != "" {
		t.Error("resolveIcon should fall back to default icon when per-notification icon doesn't exist")
	}
}

// TestResolveIcon_EmptyString verifies resolveIcon with empty string.
func TestResolveIcon_EmptyString(t *testing.T) {
	n := New("")
	resolved := n.resolveIcon("")
	// Should use the default icon
	if resolved == "" {
		t.Log("resolveIcon with empty string returned empty (may be expected if no default)")
	}
}

// TestResolveIcon_DefaultNotifierIcon verifies resolveIcon falls back to notifier default.
func TestResolveIcon_DefaultNotifierIcon(t *testing.T) {
	tmpDir := t.TempDir()
	iconFile := filepath.Join(tmpDir, "default-icon.png")
	if err := os.WriteFile(iconFile, []byte("default png"), 0644); err != nil {
		t.Fatal(err)
	}

	n := New(iconFile)
	if n.iconPath != iconFile {
		t.Fatalf("iconPath = %s, want %s", n.iconPath, iconFile)
	}

	// When per-notification icon is empty, should use notifier default
	resolved := n.resolveIcon("")
	abs, _ := filepath.Abs(iconFile)
	if resolved != abs {
		t.Errorf("resolveIcon should fall back to notifier default: got %s, want %s", resolved, abs)
	}
}

// TestResolveIcon_PerNotificationOverridesDefault verifies per-notification icon takes priority.
func TestResolveIcon_PerNotificationOverridesDefault(t *testing.T) {
	// Create two icon files
	tmpDir := t.TempDir()
	defaultIcon := filepath.Join(tmpDir, "default-icon.png")
	notifIcon := filepath.Join(tmpDir, "notif-icon.png")

	if err := os.WriteFile(defaultIcon, []byte("default"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notifIcon, []byte("notif"), 0644); err != nil {
		t.Fatal(err)
	}

	n := New(defaultIcon)
	resolved := n.resolveIcon(notifIcon)

	// Per-notification icon should take priority
	abs, _ := filepath.Abs(notifIcon)
	if resolved != abs {
		t.Errorf("Per-notification icon should override default: got %s, want %s", resolved, abs)
	}
}

// TestSend_WithPerNotificationIcon tests Send with a per-notification icon.
func TestSend_WithPerNotificationIcon(t *testing.T) {
	tmpDir := t.TempDir()
	iconFile := filepath.Join(tmpDir, "test-icon.png")
	if err := os.WriteFile(iconFile, []byte("fake png"), 0644); err != nil {
		t.Fatal(err)
	}

	n := New("")
	err := n.Send(Notification{
		Title: "Test with Icon",
		Body:  "Testing icon resolution",
		Icon:  iconFile,
	})
	// May fail in headless CI, but should not panic
	t.Logf("Send with per-notification icon: %v", err)
}

// TestSendDetection_EmptyHost tests SendDetection with empty host.
func TestSendDetection_EmptyHost(t *testing.T) {
	n := New("")
	_ = n.SendDetection("", 0, nil)
}

// TestSendDetection_MultipleCategories tests SendDetection with many categories.
func TestSendDetection_MultipleCategories(t *testing.T) {
	n := New("")
	_ = n.SendDetection("api.openai.com", 5, []string{"pii-us-core", "secret", "compliance", "xss"})
}

// TestSendBlocked_WithReason tests SendBlocked with a reason string.
func TestSendBlocked_WithReason(t *testing.T) {
	n := New("")
	_ = n.SendBlocked("api.openai.com", "SSN detected in request body")
}

// TestSendStartup_CustomPort tests SendStartup with a custom port.
func TestSendStartup_CustomPort(t *testing.T) {
	n := New("")
	_ = n.SendStartup(9090, 27)
}

// TestNotifier_EnableDisableCycle tests toggling enable/disable multiple times.
func TestNotifier_EnableDisableCycle(t *testing.T) {
	n := New("")

	// Initially enabled
	if !n.IsEnabled() {
		t.Error("Notifications should be enabled by default")
	}

	// Toggle multiple times
	n.Disable()
	if n.IsEnabled() {
		t.Error("Notifications should be disabled after Disable()")
	}

	n.Enable()
	if !n.IsEnabled() {
		t.Error("Notifications should be enabled after Enable()")
	}

	n.Disable()
	if n.IsEnabled() {
		t.Error("Notifications should be disabled after second Disable()")
	}

	n.Enable()
	if !n.IsEnabled() {
		t.Error("Notifications should be enabled after second Enable()")
	}
}

// TestSend_DisabledIsNoOp verifies that Send when disabled returns nil.
func TestSend_DisabledIsNoOp(t *testing.T) {
	n := New("")
	n.Disable()
	err := n.Send(Notification{Title: "Test", Body: "Suppressed"})
	if err != nil {
		t.Errorf("Send while disabled should be no-op (nil error), got: %v", err)
	}
}

// TestSend_PlatformSpecific tests the platform-specific notification function directly.
// Requires RAMPART_INTEGRATION=1 to avoid firing real desktop notifications.
func TestSend_PlatformSpecific(t *testing.T) {
	if os.Getenv("RAMPART_INTEGRATION") != "1" {
		t.Skip("Skipping integration test (set RAMPART_INTEGRATION=1 to run desktop notifications)")
	}

	n := New("")

	switch runtime.GOOS {
	case "linux":
		err := n.notifyLinux(Notification{Title: "Test", Body: "Linux notification"}, "")
		t.Logf("notifyLinux: %v", err)
	case "darwin":
		err := n.notifyDarwin(Notification{Title: "Test", Body: "macOS notification"})
		t.Logf("notifyDarwin: %v", err)
	case "windows":
		err := n.notifyWindows(Notification{Title: "Test", Body: "Windows notification"}, "")
		t.Logf("notifyWindows: %v", err)
	default:
		t.Skipf("Unsupported platform: %s", runtime.GOOS)
	}
}

// TestNotifyLinux_WithIcon tests notifyLinux with an icon parameter.
// Requires RAMPART_INTEGRATION=1 to avoid firing real desktop notifications.
func TestNotifyLinux_WithIcon(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}
	if os.Getenv("RAMPART_INTEGRATION") != "1" {
		t.Skip("Skipping integration test (set RAMPART_INTEGRATION=1 to run desktop notifications)")
	}

	tmpDir := t.TempDir()
	iconFile := filepath.Join(tmpDir, "icon.png")
	if err := os.WriteFile(iconFile, []byte("fake png"), 0644); err != nil {
		t.Fatal(err)
	}

	n := New("")
	err := n.notifyLinux(Notification{Title: "Test", Body: "With icon"}, iconFile)
	t.Logf("notifyLinux with icon: %v", err)
}

// TestNotifyDarwin_Escaping tests that osascript handles special characters.
func TestNotifyDarwin_Escaping(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}

	n := New("")
	err := n.notifyDarwin(Notification{
		Title: `Test "with" quotes`,
		Body:  `Line "one" and line 'two'`,
	})
	t.Logf("notifyDarwin with special chars: %v", err)
}

// TestEnsureDefaultIcon_Idempotent verifies that ensureDefaultIcon is idempotent.
func TestEnsureDefaultIcon_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	n := &Notifier{enabled: true}

	path1 := n.ensureDefaultIcon()
	if path1 == "" {
		t.Fatal("ensureDefaultIcon should return a non-empty path")
	}

	// Second call should return same path
	path2 := n.ensureDefaultIcon()
	if path2 != path1 {
		t.Errorf("ensureDefaultIcon should be idempotent: first=%s second=%s", path1, path2)
	}

	// Verify file exists
	if _, err := os.Stat(path1); err != nil {
		t.Errorf("Icon file should exist at %s: %v", path1, err)
	}
}

// TestEnsureDefaultIcon_ExistingFile verifies that ensureDefaultIcon uses existing icon.
func TestEnsureDefaultIcon_ExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	iconDir := filepath.Join(tmpDir, "aegisgate-rampart")
	if err := os.MkdirAll(iconDir, 0755); err != nil {
		t.Fatal(err)
	}
	iconFile := filepath.Join(iconDir, "rampart-shield-64.png")
	if err := os.WriteFile(iconFile, []byte("existing icon"), 0644); err != nil {
		t.Fatal(err)
	}

	n := &Notifier{enabled: true}
	path := n.ensureDefaultIcon()

	if path != iconFile {
		t.Errorf("ensureDefaultIcon should use existing file: got %s, want %s", path, iconFile)
	}
}
