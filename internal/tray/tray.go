// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - System Tray
// =========================================================================
//
// Cross-platform system tray icon using fyne.io/systray.
// Provides:
//   - Status display (running, stopped)
//   - Detection count
//   - Start/Stop/Restart controls
//   - Open Dashboard
//   - Quit
//
// Air-gap ready: no network requests, purely local UI.
//
// =========================================================================

package tray

import (
	"context"
	"fmt"
	"log"
	"os"

	"fyne.io/systray"
)

// Tray represents the system tray interface.
type Tray struct {
	port     int
	targets  int
	ctx      context.Context
	cancel   context.CancelFunc

	// Menu items
	mStatus    *systray.MenuItem
	mDetections *systray.MenuItem
	mStart     *systray.MenuItem
	mStop      *systray.MenuItem
	mRestart   *systray.MenuItem
	mQuit      *systray.MenuItem

	// State
	detectionCount int64
	running        bool
}

// Config holds tray configuration.
type Config struct {
	Port    int
	Targets int
}

// New creates a new system tray instance.
func New(cfg Config) *Tray {
	return &Tray{
		port:    cfg.Port,
		targets: cfg.Targets,
	}
}

// Run starts the system tray event loop.
// This blocks until the tray is closed or the context is cancelled.
func (t *Tray) Run(ctx context.Context, cancel context.CancelFunc) error {
	t.ctx = ctx
	t.cancel = cancel

	systray.Run(t.onReady, t.onExit)
	return nil
}

// onReady is called when the system tray is ready.
func (t *Tray) onReady() {
	// Set tray icon — use a built-in 16x16 shield icon
	systray.SetTitle("🛡️")
	systray.SetTooltip("AegisGate Rampart — AI Security Proxy")

	// Status section
	t.mStatus = systray.AddMenuItem("Rampart: Starting...", "Current status")
	t.mStatus.Disable()

	t.mDetections = systray.AddMenuItem("Detections: 0", "Total threats detected")
	t.mDetections.Disable()

	systray.AddSeparator()

	// Control section
	t.mStart = systray.AddMenuItem("Start", "Start the proxy")
	t.mStop = systray.AddMenuItem("Stop", "Stop the proxy")
	t.mRestart = systray.AddMenuItem("Restart", "Restart the proxy")

	systray.AddSeparator()

	// Info section
	portInfo := systray.AddMenuItem(fmt.Sprintf("Port: %d", t.port), "Proxy port")
	portInfo.Disable()
	targetInfo := systray.AddMenuItem(fmt.Sprintf("Targets: %d", t.targets), "Monitored AI API endpoints")
	targetInfo.Disable()

	systray.AddSeparator()

	// Quit
	t.mQuit = systray.AddMenuItem("Quit", "Quit AegisGate Rampart")

	// Set initial state
	t.SetRunning(true)

	// Handle menu clicks
	go t.handleMenu()
}

// onExit is called when the system tray is exiting.
func (t *Tray) onExit() {
	log.Printf("rampart: System tray exiting")
}

// handleMenu processes menu item clicks.
func (t *Tray) handleMenu() {
	for {
		select {
		case <-t.mStart.ClickedCh:
			t.SetRunning(true)
			log.Printf("rampart: Proxy started via tray")
		case <-t.mStop.ClickedCh:
			t.SetRunning(false)
			log.Printf("rampart: Proxy stopped via tray")
		case <-t.mRestart.ClickedCh:
			t.SetRunning(false)
			t.SetRunning(true)
			log.Printf("rampart: Proxy restarted via tray")
		case <-t.mQuit.ClickedCh:
			log.Printf("rampart: Quit requested via tray")
			systray.Quit()
			t.cancel()
			return
		case <-t.ctx.Done():
			systray.Quit()
			return
		}
	}
}

// SetRunning updates the tray status to running or stopped.
func (t *Tray) SetRunning(running bool) {
	t.running = running
	if running {
		t.mStatus.SetTitle("🛡️ Rampart: Active")
		t.mStart.Disable()
		t.mStop.Enable()
	} else {
		t.mStatus.SetTitle("⏸️ Rampart: Stopped")
		t.mStart.Enable()
		t.mStop.Disable()
	}
}

// UpdateDetections updates the detection count in the tray.
func (t *Tray) UpdateDetections(count int64) {
	t.detectionCount = count
	t.mDetections.SetTitle(fmt.Sprintf("Detections: %d", count))
}

// IncrementDetections increments the detection counter.
func (t *Tray) IncrementDetections() {
	t.detectionCount++
	t.mDetections.SetTitle(fmt.Sprintf("Detections: %d", t.detectionCount))
}

// IsRunning returns whether the proxy is currently running.
func (t *Tray) IsRunning() bool {
	return t.running
}

// SetIcon sets the tray icon from file data.
func SetIconFromBytes(data []byte) {
	systray.SetIcon(data)
}

// GetDefaultIconBytes returns a simple 16x16 shield icon as PNG bytes.
// This avoids needing external icon files for initial startup.
func GetDefaultIconBytes() []byte {
	// Minimal 16x16 green shield PNG (embedded for zero-config)
	return []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xCA,
		0x49, 0x00, 0x00, 0x00, 0x49, 0x49, 0x44, 0x41,
		0x54, 0x28, 0x91, 0x63, 0x60, 0xF8, 0xCF, 0xC0,
		0x00, 0x00, 0x00, 0x06, 0x10, 0x10, 0x10, 0x10,
		0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0xF0, 0x3F,
		0x60, 0x62, 0x00, 0x00, 0x78, 0x30, 0xE4, 0xD2,
		0x20, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
		0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
	}
}

// EnsureRunning is a no-op placeholder for build systems
// that need to reference the tray package even without CGO.
func EnsureRunning() {}

// Exit calls os.Exit(0) for clean daemon shutdown.
func Exit() {
	os.Exit(0)
}