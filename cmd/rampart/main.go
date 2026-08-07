package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/autostart"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/catrust"
	"github.com/aegisgatesecurity/aegisgate-rampart/internal/platform"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/proxy"
)

var (
	versionFlag     = "dev"
	daemonFlag      = flag.Bool("daemon", false, "Run as background daemon with system tray notifications")
	portFlag        = flag.Int("port", 8080, "Local proxy port")
	configDirFlag   = flag.String("config", "", "Configuration directory path")
	platformFlag    = flag.String("platform-url", "", "Optional Platform backend URL for telemetry")
	verboseFlag     = flag.Bool("v", false, "Verbose output")
	trustFlag       = flag.Bool("trust", false, "Install CA certificate into system trust store")
	autostartFlag   = flag.Bool("autostart", false, "Configure auto-start on boot")
	noAutostartFlag = flag.Bool("no-autostart", false, "Remove auto-start configuration")
	statusFlag      = flag.Bool("status", false, "Show current status and exit")
)

func main() {
	flag.Parse()

	if flag.Arg(0) == "version" {
		fmt.Printf("aegisgate-rampart %s\n", versionFlag)
		os.Exit(0)
	}

	// Handle one-shot commands before starting proxy
	if *trustFlag {
		handleTrust()
		return
	}
	if *autostartFlag {
		handleAutoStart(true)
		return
	}
	if *noAutostartFlag {
		handleAutoStart(false)
		return
	}
	if *statusFlag {
		handleStatus()
		return
	}

	cfg, err := config.Load(*configDirFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	if *portFlag != 0 {
		cfg.ProxyPort = *portFlag
	}
	if *platformFlag != "" {
		cfg.PlatformURL = *platformFlag
	}
	if *daemonFlag {
		cfg.DaemonMode = true
	}
	if *verboseFlag {
		cfg.Verbose = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *daemonFlag {
		runDaemon(ctx, cancel, cfg)
	} else {
		runForeground(ctx, cancel, cfg)
	}
}

// runForeground runs the proxy in foreground mode (terminal output).
func runForeground(ctx context.Context, cancel context.CancelFunc, cfg *config.Config) {
	p, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing proxy: %v\n", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, shutdownSignals()...)

	// SIGHUP: hot-reload configuration
	reloadSig := reloadSignal()
	reloadChan := make(chan os.Signal, 1)
	if reloadSig != nil {
		signal.Notify(reloadChan, reloadSig)
	}

	go func() {
		for {
			select {
			case <-sigChan:
				fmt.Println("\nShutting down...")
				cancel()
				p.Shutdown()
				return
			case <-reloadChan:
				fmt.Println("SIGHUP received, reloading configuration...")
				configPath := config.ConfigPath()
				newCfg, err := config.Load(configPath)
				if err != nil {
					log.Printf("rampart: reload failed: %v", err)
					continue
				}
				p.ReloadConfig(newCfg)
			}
		}
	}()

	fmt.Printf("aegisgate-rampart starting on :%d\n", cfg.ProxyPort)
	fmt.Println("Press Ctrl+C to stop")

	if err := p.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
		os.Exit(1)
	}
}

// runDaemon runs the proxy in daemon mode (system tray + notifications).
func runDaemon(ctx context.Context, cancel context.CancelFunc, cfg *config.Config) {
	pidFile := filepath.Join(getConfigDir(), "rampart.pid")

	// Check if already running
	if running, pid := IsRunning(pidFile); running {
		fmt.Fprintf(os.Stderr, "rampart: already running (PID %d)\n", pid)
		fmt.Fprintf(os.Stderr, "Use 'kill %d' or 'rampart --no-autostart' to stop it.\n", pid)
		os.Exit(1)
	}

	d := NewDaemon(cfg)

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, shutdownSignals()...)
		<-sigChan
		log.Printf("rampart: Received shutdown signal")
		cancel()
	}()

	log.Printf("aegisgate-rampart starting in daemon mode on :%d", cfg.ProxyPort)

	if err := d.Run(ctx, cancel); err != nil {
		log.Fatalf("daemon error: %v", err)
	}
}

// getConfigDir returns the platform-appropriate configuration directory path.
func getConfigDir() string {
	return platform.ConfigDir()
}

// handleTrust handles the --trust flag: install CA cert into system trust store.
func handleTrust() {
	certPath := catrust.DefaultCACertPath()
	status := catrust.CheckTrust(certPath)
	fmt.Printf("CA Certificate: %s\n", status.CertPath)
	fmt.Printf("Platform: %s\n", status.Platform)
	fmt.Printf("Trusted: %v\n", status.Trusted)
	fmt.Printf("Status: %s\n\n", status.Message)

	if status.Trusted {
		fmt.Println("✅ CA certificate is already trusted. No action needed.")
		return
	}

	result := catrust.SetupTrust(certPath)
	if result.Success {
		fmt.Printf("✅ %s\n", result.Message)
	} else {
		fmt.Printf("❌ %s\n", result.Message)
		fmt.Printf("\n%s", catrust.GetInstructions(certPath))
	}
}

// handleAutoStart handles the --autostart and --no-autostart flags.
func handleAutoStart(enable bool) {
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not determine executable path: %v\n", err)
		os.Exit(1)
	}
	mgr := autostart.New(execPath)
	if enable {
		if err := mgr.Enable(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Auto-start enabled on %s\n", runtime.GOOS)
		if runtime.GOOS == "windows" {
			fmt.Printf("   Registry entry created at HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n")
		}
	} else {
		if err := mgr.Disable(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Auto-start disabled on %s\n", runtime.GOOS)
	}
}

// handleStatus handles the --status flag: show proxy status and trust status.
func handleStatus() {
	certPath := catrust.DefaultCACertPath()
	trustStatus := catrust.CheckTrust(certPath)

	fmt.Printf("AegisGate Rampart Status\n")
	fmt.Printf("========================\n")
	fmt.Printf("CA Certificate: %s\n", trustStatus.CertPath)
	fmt.Printf("CA Trusted: %v\n", trustStatus.Trusted)
	fmt.Printf("Platform: %s\n", trustStatus.Platform)

	pidFile := filepath.Join(getConfigDir(), "rampart.pid")
	if running, pid := IsRunning(pidFile); running {
		fmt.Printf("Daemon: running (PID %d)\n", pid)
	} else {
		fmt.Printf("Daemon: not running\n")
	}

	execPath, _ := os.Executable()
	mgr := autostart.New(execPath)
	fmt.Printf("Auto-start: %v\n", mgr.IsEnabled())
}
