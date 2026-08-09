// SPDX-License-Identifier: Apache-2.0
// AegisGate Rampart - Webhook CLI Commands

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/aegisgatesecurity/aegisgate-rampart/internal/webhook"
)

func runWebhookCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("webhook subcommand required: add, list, remove, test, enable, disable")
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "add":
		return runWebhookAdd(subargs)
	case "list":
		return runWebhookList(subargs)
	case "remove":
		return runWebhookRemove(subargs)
	case "test":
		return runWebhookTest(subargs)
	case "enable":
		return runWebhookEnable(subargs)
	case "disable":
		return runWebhookDisable(subargs)
	default:
		return fmt.Errorf("unknown webhook subcommand: %s", subcmd)
	}
}

func runWebhookAdd(args []string) error {
	fs := flag.NewFlagSet("webhook add", flag.ExitOnError)
	name := fs.String("name", "", "Webhook name (required)")
	url := fs.String("url", "", "Webhook URL (required)")
	secret := fs.String("secret", "", "Secret for HMAC signing")
	skipTLS := fs.Bool("skip-tls-verify", false, "Skip TLS verification")
	timeout := fs.Duration("timeout", 30*time.Second, "Request timeout")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *name == "" || *url == "" {
		return fmt.Errorf("-name and -url are required")
	}

	cfgPath := filepath.Join(getConfigDir(), "webhooks.json")

	// Load existing config
	cfg, err := webhook.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Create new webhook
	wh := webhook.WebhookConfig{
		ID:            fmt.Sprintf("wh_%d", time.Now().UnixNano()),
		Name:          *name,
		URL:           *url,
		Enabled:       true,
		Method:        "POST",
		Secret:        *secret,
		SkipTLSVerify: *skipTLS,
		Timeout:       *timeout,
		Headers:       make(map[string]string),
	}

	// Add to config
	cfg.Webhooks = append(cfg.Webhooks, wh)

	// Save config
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	err = os.WriteFile(cfgPath, data, 0600)
	if err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Printf("✅ Webhook '%s' added successfully\n", *name)
	fmt.Printf("   ID: %s\n", wh.ID)
	fmt.Printf("   URL: %s\n", *url)

	return nil
}

func runWebhookList(args []string) error {
	cfgPath := filepath.Join(getConfigDir(), "webhooks.json")

	cfg, err := webhook.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if len(cfg.Webhooks) == 0 {
		fmt.Println("No webhooks configured")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tURL\tENABLED\tTIMEOUT")

	for _, wh := range cfg.Webhooks {
		enabled := "✓"
		if !wh.Enabled {
			enabled = "✗"
		}

		timeout := wh.Timeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			wh.ID, wh.Name, truncateURL(wh.URL, 40), enabled, timeout)
	}

	w.Flush()
	return nil
}

func runWebhookRemove(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("webhook ID required")
	}

	cfgPath := filepath.Join(getConfigDir(), "webhooks.json")

	cfg, err := webhook.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	found := false
	newWebhooks := make([]webhook.WebhookConfig, 0, len(cfg.Webhooks))

	for _, wh := range cfg.Webhooks {
		if wh.ID == args[0] {
			found = true
			fmt.Printf("Removing webhook: %s (%s)\n", wh.Name, wh.ID)
		} else {
			newWebhooks = append(newWebhooks, wh)
		}
	}

	if !found {
		return fmt.Errorf("webhook '%s' not found", args[0])
	}

	cfg.Webhooks = newWebhooks

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	err = os.WriteFile(cfgPath, data, 0600)
	if err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("✅ Webhook removed successfully")
	return nil
}

func runWebhookTest(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("webhook ID required")
	}

	cfgPath := filepath.Join(getConfigDir(), "webhooks.json")

	cfg, err := webhook.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var target *webhook.WebhookConfig
	for i := range cfg.Webhooks {
		if cfg.Webhooks[i].ID == args[0] {
			target = &cfg.Webhooks[i]
			break
		}
	}

	if target == nil {
		return fmt.Errorf("webhook '%s' not found", args[0])
	}

	if !target.Enabled {
		return fmt.Errorf("webhook '%s' is disabled", target.Name)
	}

	// Create test event
	event := webhook.Event{
		Timestamp: time.Now(),
		EventType: "test",
		Host:      "rampart-test",
		Blocked:   false,
		Severity:  "info",
		Message:   "This is a test webhook from AegisGate Rampart",
		RawData: map[string]interface{}{
			"version": "0.6.0",
			"test":    true,
		},
	}

	// Create manager and send
	mgr := webhook.NewManager(cfg)
	err = mgr.Send(context.TODO(), event)
	if err != nil {
		return fmt.Errorf("send test webhook: %w", err)
	}

	fmt.Printf("✅ Test webhook sent successfully to '%s'\n", target.Name)
	return nil
}

func runWebhookEnable(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("webhook ID required")
	}
	return setWebhookEnabled(args[0], true)
}

func runWebhookDisable(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("webhook ID required")
	}
	return setWebhookEnabled(args[0], false)
}

func setWebhookEnabled(id string, enabled bool) error {
	cfgPath := filepath.Join(getConfigDir(), "webhooks.json")

	cfg, err := webhook.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	found := false
	for i := range cfg.Webhooks {
		if cfg.Webhooks[i].ID == id {
			cfg.Webhooks[i].Enabled = enabled
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("webhook '%s' not found", id)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	err = os.WriteFile(cfgPath, data, 0600)
	if err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	status := "enabled"
	if !enabled {
		status = "disabled"
	}
	fmt.Printf("✅ Webhook %s\n", status)
	return nil
}

func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen-3] + "..."
}
