# Changelog

All notable changes to AegisGate Rampart are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.1] - 2026-08-07

### Added — P0: Audit Log & Platform Forwarding

- Local audit log (`internal/auditlog`): JSONL persistence of detection events
  - Writes to `~/.local/share/aegisgate-rampart/audit.log` (Linux), `~/Library/Application Support/aegisgate-rampart/audit.log` (macOS), `%AppData%\AegisGate Rampart\audit.log` (Windows)
  - Size-based rotation (10 MB default) with timestamped backups
  - Fsync after every write for durability
  - **No prompt text, no PII values, no credentials** — only metadata (category, rule, severity, host, path)
- Platform forwarding (`internal/platformforward`): push detection metadata to AegisGate Platform
  - Opt-in via `platform_url` config field (empty = disabled, air-gap compatible)
  - Async HTTP POST with 5s timeout
  - **Same privacy guarantee**: only metadata forwarded, never prompt text or PII values
  - Non-blocking on error (connection refused, server error → log and continue)
- Proxy integration: every detection now writes to audit log AND forwards to Platform (if configured)
- Audit log closed on graceful shutdown

## [0.2.0] - 2026-08-07

### Added — Phase 4: Production Hardening

- Graceful shutdown with connection draining (15s timeout via `http.Server.Shutdown`)
- Rate limiting on `/detect` and `/stats` API endpoints (30 req/s burst, 429 on exceed)
- Configuration hot-reload on SIGHUP (Unix) — reloads `config.json` without restart
- `ReloadConfig()` method on Proxy for live target updates
- `ConfigPath()` helper in config package for reload file watching
- `reloadSignal()` platform abstraction (SIGHUP on Unix, nil on Windows)
- Security audit: verified no prompt text in `log.Printf` output — only category/rule names
- Security audit: `ProxyStats` contains only counts, no sensitive data
- Security tests: `TestSecurityAudit_NoPromptTextInLogs`, `TestSecurityAudit_RateLimitPreventsAbuse`, `TestSecurityAudit_NoDataRetention`
- Rate limit tests: method not allowed, 429 response, concurrent burst behavior
- Graceful shutdown test: context cancellation + drain verification
- Config reload test: target domain addition/removal verification
- Signal tests for SIGHUP (Unix) and nil reload (Windows)

## [0.1.0] - 2026-08-07

### Added
- HTTPS MITM proxy for 27 AI API endpoints
- CA certificate generation and trust flow (`--trust`, `--status`)
- Detection engine: 153 regex patterns + Char CNN-BiLSTM ML heuristic
- PII scanner (SSN, credit cards, emails, phones, international PII)
- Secret detector (API keys, bearer tokens, JWTs)
- Hallucination detector, toxicity filter, token limiter
- Response guard (scan AI responses before delivery)
- Desktop notifications (Linux notify-send, macOS osascript, Windows beeep)
- System tray integration (fyne.io/systray)
- Auto-start on boot (systemd, launchd, Windows Registry)
- Daemon mode with PID file lifecycle (`--daemon`)
- HTTP API endpoints (`/detect`, `/stats`)
- E2E integration tests (gated by `RAMPART_INTEGRATION=1`)
- Cross-platform support: Linux, macOS, Windows
- Platform-aware config directories (XDG on Linux, AppData on Windows, Library on macOS)
- Platform-aware signal handling (SIGINT+SIGTERM on Unix, SIGINT on Windows)
- Windows Registry auto-start (direct HKCU write with .reg fallback)
- macOS ONNX runtime search paths (Homebrew Intel + Apple Silicon)
- Windows ONNX runtime search paths (.dll)
- CI: Linux (ubuntu-latest), macOS (macos-latest + CGO), cross-compile (Windows, ARM64)
- Release workflow: Linux/Windows (CGO_ENABLED=0), macOS (CGO_ENABLED=1 on macos-latest)
- DCO enforcement in CI
- 80% coverage floor in CI (exempting cmd/rampart, internal/tray)
- golangci-lint + go vet + gofmt checks in CI

### Fixed
- TotalDetections undercount bug (DetectAll results not counted)
- Notification icon not rendering (RGB→RGBA with transparent background)
- DEECTION→DETECTION typo in terminal output
- Build-breaking missing `//go:build linux` tag on notify_platform_test.go
- Hardcoded `~/.config/aegisgate-rampart` paths replaced with `platform.ConfigDir()`
- ineffectual assignment in E2E test
- Windows/darwin test name collisions