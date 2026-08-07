// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Auto-Start
// =========================================================================
//
// Manages auto-start on boot across platforms:
//   - macOS: launchd plist in ~/Library/LaunchAgents/
//   - Linux: systemd unit in ~/.config/systemd/user/
//   - Windows: Registry Run key (HKCU\Software\Microsoft\Windows\CurrentVersion\Run)
//
// =========================================================================

package autostart

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/platform"
)

const (
	plistName  = "com.aegisgate.rampart"
	unitName   = "rampart.service"
	regKeyName = "AegisGateRampart"
	regKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
)

// Manager handles auto-start configuration.
type Manager struct {
	binPath string
}

// New creates a new auto-start manager.
// binPath is the path to the rampart binary.
func New(binPath string) *Manager {
	return &Manager{binPath: binPath}
}

// Enable configures auto-start for the current platform.
func (m *Manager) Enable() error {
	switch runtime.GOOS {
	case "darwin":
		return m.enableDarwin()
	case "linux":
		return m.enableLinux()
	case "windows":
		return m.enableWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// Disable removes auto-start configuration.
func (m *Manager) Disable() error {
	switch runtime.GOOS {
	case "darwin":
		return m.disableDarwin()
	case "linux":
		return m.disableLinux()
	case "windows":
		return m.disableWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// IsEnabled returns whether auto-start is configured.
func (m *Manager) IsEnabled() bool {
	switch runtime.GOOS {
	case "darwin":
		return m.isEnabledDarwin()
	case "linux":
		return m.isEnabledLinux()
	case "windows":
		return m.isEnabledWindows()
	default:
		return false
	}
}

// --- macOS (launchd) ---

func (m *Manager) plistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", plistName+".plist")
}

func (m *Manager) enableDarwin() error {
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s/rampart.log</string>
    <key>StandardErrorPath</key>
    <string>%s/rampart.log</string>
</dict>
</plist>`, plistName, m.binPath, platform.ConfigDir(), platform.ConfigDir())

	return os.WriteFile(m.plistPath(), []byte(plist), 0644)
}

func (m *Manager) disableDarwin() error {
	return os.Remove(m.plistPath())
}

func (m *Manager) isEnabledDarwin() bool {
	_, err := os.Stat(m.plistPath())
	return err == nil
}

// --- Linux (systemd) ---

func (m *Manager) unitPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "systemd", "user", unitName)
}

func (m *Manager) enableLinux() error {
	unitDir := filepath.Dir(m.unitPath())
	if err := os.MkdirAll(unitDir, 0755); err != nil {
		return err
	}

	unit := fmt.Sprintf(`[Unit]
Description=AegisGate Rampart - AI Security Proxy
After=network.target

[Service]
ExecStart=%s --daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, m.binPath)

	return os.WriteFile(m.unitPath(), []byte(unit), 0644)
}

func (m *Manager) disableLinux() error {
	return os.Remove(m.unitPath())
}

func (m *Manager) isEnabledLinux() bool {
	_, err := os.Stat(m.unitPath())
	return err == nil
}

// --- Windows (Registry) ---

func (m *Manager) enableWindows() error {
	// Try direct registry write first (seamless, no user action needed)
	if err := enableWindowsRegistry(m.binPath + " --daemon"); err == nil {
		return nil
	}
	// Fallback: generate .reg file for manual import
	regContent := fmt.Sprintf(`Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"%s"="%s --daemon"
`, regKeyName, m.binPath)

	regPath := filepath.Join(platform.ConfigDir(), "rampart-autostart.reg")
	if err := os.MkdirAll(filepath.Dir(regPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(regPath, []byte(regContent), 0644)
}

func (m *Manager) disableWindows() error {
	// Try direct registry removal first
	_ = disableWindowsRegistry()
	// Also remove .reg file if it exists
	regPath := filepath.Join(platform.ConfigDir(), "rampart-autostart.reg")
	os.Remove(regPath)
	return nil
}

func (m *Manager) isEnabledWindows() bool {
	// Check registry first, then fall back to .reg file
	if isEnabledWindowsRegistry() {
		return true
	}
	regPath := filepath.Join(platform.ConfigDir(), "rampart-autostart.reg")
	_, err := os.Stat(regPath)
	return err == nil
}
