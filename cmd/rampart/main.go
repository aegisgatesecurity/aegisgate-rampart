package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-rampart/pkg/proxy"
)

var (
	version   = "dev"
	daemon    = flag.Bool("daemon", false, "Run as background daemon with system notifications")
	port      = flag.Int("port", 8080, "Local proxy port")
	configDir = flag.String("config", "", "Configuration directory path")
	platform  = flag.String("platform-url", "", "Optional Platform backend URL for telemetry")
	verbose   = flag.Bool("v", false, "Verbose output")
)

func main() {
	flag.Parse()

	if flag.Arg(0) == "version" {
		fmt.Printf("aegisgate-rampart %s\n", version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	if *port != 0 {
		cfg.ProxyPort = *port
	}
	if *platform != "" {
		cfg.PlatformURL = *platform
	}
	if *daemon {
		cfg.DaemonMode = true
	}
	if *verbose {
		cfg.Verbose = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	p, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing proxy: %v\n", err)
		os.Exit(1)
	}

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		cancel()
		p.Shutdown()
	}()

	fmt.Printf("aegisgate-rampart %s starting on :%d\n", version, cfg.ProxyPort)
	if *daemon {
		fmt.Println("Running in daemon mode (system notifications enabled)")
	}
	fmt.Println("Press Ctrl+C to stop")

	if err := p.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
		os.Exit(1)
	}
}
