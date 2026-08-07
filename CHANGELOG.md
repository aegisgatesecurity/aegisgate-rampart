# Changelog

All notable changes to AegisGate Rampart are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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