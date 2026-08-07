// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart - Daemon Mode
// =========================================================================
//
// Handles daemon lifecycle: PID file, signal handling, and graceful
// startup/shutdown for background mode (--daemon flag).
//
// =========================================================================

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/notify"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/tray"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/proxy"
)

// Daemon manages the background proxy service.
type Daemon struct {
	cfg     *config.Config
	proxy   *proxy.Proxy
	notify  *notify.Notifier
	tray    *tray.Tray
	pidFile string
}

// NewDaemon creates a new daemon instance.
func NewDaemon(cfg *config.Config) *Daemon {
	pidDir := getConfigDir()
	return &Daemon{
		cfg:     cfg,
		pidFile: filepath.Join(pidDir, "rampart.pid"),
		notify:  notify.New(""),
		tray:    tray.New(tray.Config{Port: cfg.ProxyPort, Targets: len(cfg.Targets)}),
	}
}

// Run starts the daemon: PID file, proxy, tray, notifications.
func (d *Daemon) Run(ctx context.Context, cancel context.CancelFunc) error {
	// Write PID file
	if err := d.writePID(); err != nil {
		return fmt.Errorf("writing PID file: %w", err)
	}
	defer d.removePID()

	// Start proxy
	p, err := proxy.New(d.cfg)
	if err != nil {
		return fmt.Errorf("initializing proxy: %w", err)
	}
	d.proxy = p

	// Start proxy in background
	go func() {
		if err := p.Start(ctx); err != nil {
			log.Printf("rampart: Proxy error: %v", err)
		}
	}()

	// Send startup notification
	d.notify.SendStartup(d.cfg.ProxyPort, len(d.cfg.Targets))

	// Hook detection events into tray/notifications
	go d.watchDetections(ctx)

	// Start system tray (blocks until quit)
	log.Printf("rampart: Starting system tray...")
	if err := d.tray.Run(ctx, cancel); err != nil {
		log.Printf("rampart: Tray error: %v", err)
	}

	return nil
}

// watchDetections polls proxy stats and sends notifications for new detections.
func (d *Daemon) watchDetections(ctx context.Context) {
	var lastCount int64
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if d.proxy == nil {
				continue
			}
			stats := d.proxy.GetStats()
			if stats.Detections > lastCount {
				newDetections := stats.Detections - lastCount
				if newDetections > 0 {
					d.notify.SendDetection("AI API", int(newDetections), nil)
					d.tray.UpdateDetections(stats.Detections)
				}
				lastCount = stats.Detections
			}
		}
	}
}

// writePID writes the current process ID to the PID file.
func (d *Daemon) writePID() error {
	dir := filepath.Dir(d.pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(d.pidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
}

// removePID removes the PID file.
func (d *Daemon) removePID() {
	os.Remove(d.pidFile)
}

// IsRunning checks if a daemon is already running by reading the PID file.
func IsRunning(pidFile string) (bool, int) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false, 0
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return false, 0
	}
	// Check if process is alive
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, 0
	}
	// Signal 0 checks if process exists without sending a signal
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return false, 0
	}
	return true, pid
}
