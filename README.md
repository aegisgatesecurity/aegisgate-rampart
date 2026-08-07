# AegisGate Rampart

> Local AI security proxy — intercept, detect, protect.

Rampart is a **local HTTPS proxy** that intercepts traffic to AI API services, runs real-time detection for PII, secrets, XSS, and compliance violations, and alerts you before sensitive data leaves your machine.

**Same detection engine as AegisGate Platform v4.0.0** — 154 regex patterns + Char CNN-BiLSTM neural network.

## Platform Support

| Platform | Config Directory | Auto-Start | Notifications | CA Trust | System Tray |
|----------|-----------------|-------------|-------------|----------|-------------|
| **Linux** | `~/.config/aegisgate-rampart/` | systemd | notify-send | update-ca-certificates | fyne/systray (CGO) |
| **macOS** | `~/Library/Application Support/aegisgate-rampart/` | launchd | osascript | security add-trusted-cert | fyne/systray (CGO) |
| **Windows** | `%AppData%\AegisGate Rampart\` | Registry Run key | beeep (Win32 toast) | certutil -addstore | fyne/systray |

**Build requirements**: Linux and Windows build with `CGO_ENABLED=0`. macOS requires `CGO_ENABLED=1` (systray uses Objective-C).

## Quick Start

```bash
# Build (Linux/Windows — no CGO needed)
CGO_ENABLED=0 go build -o bin/rampart ./cmd/rampart

# Build (macOS — CGO required for system tray)
CGO_ENABLED=1 go build -o bin/rampart ./cmd/rampart

# Foreground mode (terminal output)
./bin/rampart

# Daemon mode (system tray + notifications)
./bin/rampart --daemon

# Install CA cert (required for HTTPS interception)
./bin/rampart --trust

# Check status
./bin/rampart --status

# Auto-start on boot
./bin/rampart --autostart
```

### Cross-Compilation

```bash
# Linux ARM64 (Raspberry Pi, ARM servers)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/rampart-arm64 ./cmd/rampart

# Windows amd64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/rampart.exe ./cmd/rampart

# macOS (requires CGO — build on macOS or use CI)
# See .github/workflows/release.yml for macOS build instructions
```

## What It Does

```
Your Machine                                          AI APIs
┌─────────────────────────────────────────────────────────────┐
│  Claude Desktop ─┐                                          │
│  ChatGPT App ────┤     ┌──────────────────┐               │
│  VS Code + Ext ──┼────▶│     RAMPART      │──────▶  api.openai.com
│  CLI (curl) ─────┤     │   :8080 proxy     │──────▶  api.anthropic.com
│  Docker ─────────┘     │                   │──────▶  api.deepseek.com
│                        │ 154 regex patterns│──────▶  ...24 more
│                        │ Char CNN-BiLSTM    │
│                        │ PII / Secrets /   │
│                        │ XSS / Compliance  │
│                        └──────────────────┘
│                              │
│                        ┌─────▼─────┐
│                        │ Alert 🔔 │  Desktop notification
│                        │ Log    📄 │  Terminal output
│                        │ Block   🚫│  (strict mode)
│                        └───────────┘
└─────────────────────────────────────────────────────────────────┘
```

## Detection Capabilities

| Category | Patterns | Detects |
|----------|----------|---------|
| **Secrets** | 45 | AWS keys, GitHub tokens, OAuth, JWT, database URLs |
| **PII (US Core)** | 15 | SSN, email, phone, DOB, name |
| **PII (US Extended)** | 13 | Driver license, passport, medical record |
| **PII (Financial)** | 9 | Credit card (Luhn validated), bank account |
| **PII (International)** | 24 | National IDs for 15 countries |
| **XSS** | 12 | Script injection, event handlers, data URIs |
| **Compliance** | 35 | GDPR, HIPAA, PCI-DSS, SOX identifiers |
| **ML (Neural)** | 1 model | Char CNN-BiLSTM adversarial prompt detection |

## Two Modes

### Foreground Mode
```bash
./bin/rampart
```
Terminal output with detection results. Press Ctrl+C to stop.

### Daemon Mode
```bash
./bin/rampart --daemon
```
System tray icon, desktop notifications, auto-start on boot. Runs silently in background.

## CLI Reference

```
rampart                          # Foreground mode
rampart --daemon                 # Daemon mode (tray + notifications)
rampart --port 9090              # Custom port (default: 8080)
rampart --trust                  # Install CA cert into OS trust store
rampart --autostart              # Configure auto-start on boot
rampart --no-autostart           # Remove auto-start
rampart --status                 # Show daemon PID, trust status, autostart
rampart version                  # Print version
rampart --platform-url https://  # Opt-in Platform telemetry
rampart -v                       # Verbose output
```

## API Endpoints (IDE Integration)

IDE extensions call these endpoints — no ML model bundled in extensions:

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/detect` | Scan text: `{"text": "..."}` → detection results |
| `GET` | `/stats` | Proxy statistics: requests, detections, blocked |

### Example
```bash
curl -X POST http://localhost:8080/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "My SSN is 123-45-6789"}'

# Response:
{
  "total_detections": 1,
  "blocked": false,
  "results": [{"category": "pii-us-core", "severity": "high", "text": "SSN", ...}],
  "pii_categories": ["ssn"],
  ...
}
```

## 27 Target Endpoints

Covers all 10 AI providers from Lens v0.3.0 with both API and web surfaces:

| Provider | API Endpoints | Web Endpoints |
|----------|--------------|---------------|
| OpenAI/ChatGPT | api.openai.com | chat.openai.com, chatgpt.com |
| Anthropic/Claude | api.anthropic.com | claude.ai |
| Gemini | generativelanguage.googleapis.com | gemini.google.com |
| Copilot | api.copilot.microsoft.com | copilot.microsoft.com, copilot.cloud.microsoft |
| Perplexity | api.perplexity.ai | perplexity.ai, www.perplexity.ai |
| Grok | api.x.ai | grok.com, www.grok.com |
| Mistral | api.mistral.ai, codestral.mistral.ai | chat.mistral.ai, le-chat.mistral.ai |
| DeepSeek | api.deepseek.com | chat.deepseek.com |
| Duck.ai | api.duck.ai | duck.ai, www.duck.ai |
| Meta AI | — | meta.ai, www.meta.ai |

## Privacy (12 Non-Negotiables)

Rampart enforces the same 12 privacy rules as Lens and Platform:

1. No prompt text stored or sent
2. No URLs logged
3. No page content stored
4. No PII stored
5. No credentials stored
6. No fingerprinting
7. No cross-site tracking
8. No provider metadata collected
9. No keystroke logging
10. No mouse tracking
11. No session IDs stored
12. No IP addresses logged

**Air-gap mode**: When `--platform-url` is not set, Rampart makes zero network calls. All detection is local.

## Product Family

| Product | Surface | Approach | Detection |
|---------|---------|----------|-----------|
| **Lens** | Browser | DOM blocking (before send) | 154 regex + JS ML |
| **Rampart** | Desktop, CLI, IDE | HTTPS proxy (after send) | 154 regex + Go ML |
| **Platform** | Server | API gateway | 154 regex + Go ML |

**Lens blocks before send. Rampart alerts after send.** Together = full-spectrum coverage.

## Build & Test

```bash
# Build (non-CGO, no ONNX dependency)
CGO_ENABLED=0 go build -o bin/rampart ./cmd/rampart/

# Build (with CGO, ONNX ML inference)
CGO_ENABLED=1 go build -o bin/rampart ./cmd/rampart/

# Run unit tests
CGO_ENABLED=0 go test ./pkg/detector/ ./pkg/proxy/

# Run integration tests
RAMPART_INTEGRATION=1 CGO_ENABLED=0 go test -v ./pkg/proxy/

# Run fuzz targets
go test -fuzz=FuzzParseConfig -fuzztime=60s ./pkg/config/
go test -fuzz=FuzzScanRequest -fuzztime=60s ./pkg/detector/

# Cross-compile for Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/rampart.exe ./cmd/rampart/

# Cross-compile for Linux ARM64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/rampart-arm64 ./cmd/rampart/

# Lint
golangci-lint run ./...
```

## Project Structure

```
aegisgate-rampart/
├── cmd/rampart/           # CLI entry point + daemon lifecycle
├── pkg/
│   ├── config/            # Configuration (27 endpoints, 12 privacy rules)
│   ├── detector/          # Detection engine wiring
│   ├── proxy/             # HTTPS MITM proxy + /detect + /stats APIs
│   └── telemetry/         # Platform telemetry (no-op when air-gap)
├── internal/
│   ├── autostart/         # Auto-start (systemd, launchd, Registry)
│   ├── catrust/           # CA trust setup (Linux, macOS, Windows)
│   ├── certificate/        # ECDSA P-256 CA generation
│   ├── certinit/          # First-run certificate setup
│   ├── detectors/         # 154 regex patterns (from Platform v4.0.0)
│   ├── logging/           # Minimal stderr shim
│   ├── ml/                # Char CNN-BiLSTM (ONNX + heuristic)
│   ├── notify/            # Desktop notifications (3 platforms)
│   ├── platform/          # Platform-aware paths (ConfigDir, DataDir, CacheDir)
│   ├── response/          # PII scanner, secret detector, guard
│   └── tray/              # System tray (fyne.io/systray)
├── configs/default.json   # Default configuration
├── Dockerfile             # Multi-stage scratch container
└── .github/workflows/     # CI/CD workflows
```

## License

Apache-2.0