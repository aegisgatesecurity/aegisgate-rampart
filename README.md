# AegisGate Rampart

> Local AI security proxy — intercept, detect, **block**.

Rampart is a **local HTTPS MITM proxy** that intercepts traffic to 27 AI API endpoints, runs real-time detection for PII, secrets, XSS, and compliance violations, and can **actively block** threats before they reach the AI service — or before the AI's response reaches you.

**Same detection engine as AegisGate Platform v4.0.0** — 153 regex patterns + Char CNN-BiLSTM neural network.

## Operating Modes

| Mode | Flag | Behavior | Use Case |
|------|------|----------|----------|
| **Monitor** | _(default)_ | Log & alert, allow all traffic | Developer visibility |
| **Block** | `--block` | Log, alert, **actively block threats** | Security enforcement |

```bash
# Monitor mode (default) — log only
./rampart

# Block mode — actively block PII, secrets, XSS
./rampart --block

# Block mode with custom threshold
./rampart --block --mode=block
```

### Block Mode Configuration

```json
{
  "mode": "block",
  "block": {
    "threshold": "high",
    "categories": [],
    "status_code": 403,
    "include_detections": true,
    "message": "Request blocked by AegisGate Rampart",
    "block_response": "both"
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `threshold` | `"high"` | Minimum severity to block: `"low"`, `"medium"`, `"high"`, `"critical"` |
| `categories` | `[]` (all) | Categories to block: `"pii"`, `"secrets"`, `"xss"`, `"toxicity"`, `"ml_threat"` |
| `status_code` | `403` | HTTP status code for blocked responses |
| `include_detections` | `true` | Include detection details in block response |
| `message` | `"Request blocked by AegisGate Rampart"` | Custom block message |
| `block_response` | `"both"` | Block direction: `"request"`, `"response"`, or `"both"` |

### Block Mode Response

When a request is blocked, Rampart returns a structured JSON response:

```json
{
  "direction": "request",
  "host": "api.openai.com",
  "path": "/v1/chat/completions",
  "blocked": true,
  "reason": "pii: ssn detected in response",
  "severity": "critical",
  "message": "Request blocked by AegisGate Rampart",
  "results": [
    {"category": "pii", "severity": "critical", "rule": "pii_ssn", "text": "123-45-6789"}
  ]
}
```

## Platform Support

| Platform | Config Directory | Auto-Start | Notifications | CA Trust | System Tray |
|----------|-----------------|-------------|-------------|----------|-------------|
| **Linux** | `~/.config/aegisgate-rampart/` | systemd | notify-send | update-ca-certificates | fyne/systray (CGO) |
| **macOS** | `~/Library/Application Support/aegisgate-rampart/` | launchd | osascript | security add-trusted-cert | fyne/systray (CGO) |
| **Windows** | `%AppData%\AegisGate Rampart\` | Registry Run key | beeep (Win32 toast) | certutil -addstore | fyne/systray |

**Build requirements**: Linux and Windows build with `CGO_ENABLED=0`. macOS requires `CGO_ENABLED=1` (systray uses Objective-C).

## Quick Start

```bash
# Build
CGO_ENABLED=0 go build -o bin/rampart ./cmd/rampart

# Monitor mode (default)
./bin/rampart

# Block mode — actively block threats
./bin/rampart --block

# Install CA cert (required for HTTPS interception)
./bin/rampart --trust

# Custom port + block mode + rate limiting
./bin/rampart --port 9090 --block --rate-limit=10000

# With Platform telemetry (opt-in, metadata only)
./bin/rampart --platform-url https://platform.aegisgate.dev --platform-api-key rag_...

# Daemon mode (system tray + notifications)
./bin/rampart --daemon --block

# Check status
./bin/rampart --status

# Auto-start on boot
./bin/rampart --autostart

# Print version
./bin/rampart version
```

## What It Does

```
Your Machine                                          AI APIs
┌─────────────────────────────────────────────────────────────────┐
│  Claude Desktop ─┐                                              │
│  ChatGPT App ────┤     ┌──────────────────────┐               │
│  VS Code + Ext ──┼────▶│      RAMPART         │──────▶  api.openai.com
│  CLI (curl) ─────┤     │    :8080 proxy        │──────▶  api.anthropic.com
│  Docker ─────────┘     │                       │──────▶  api.deepseek.com
│                        │ 153 regex patterns    │──────▶  ...24 more
│                        │ Char CNN-BiLSTM        │
│                        │ PII / Secrets /       │
│                        │ XSS / Compliance      │
│                        │                       │
│                        │  ┌── MONITOR ──┐      │
│                        │  │  Log + Alert │      │
│                        │  └─────────────┘      │
│                        │  ┌── BLOCK ────┐      │
│                        │  │  403 + JSON  │      │
│                        │  └─────────────┘      │
│                        └──────────────────────┘
│                              │
│                        ┌─────▼─────┐
│                        │ Audit Log 📄│
│                        │ Platform 📡 │  (opt-in)
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

## CLI Reference

```
rampart                              # Monitor mode (default)
rampart --block                      # Block mode (actively block threats)
rampart --mode=monitor               # Explicit monitor mode
rampart --mode=block                 # Explicit block mode
rampart --port 9090                  # Custom port (default: 8080)
rampart --rate-limit 10000           # Rate limit (requests/second)
rampart --trust                      # Install CA cert into OS trust store
rampart --autostart                  # Configure auto-start on boot
rampart --no-autostart               # Remove auto-start
rampart --status                     # Show daemon PID, trust, autostart status
rampart --daemon                     # Daemon mode (tray + notifications)
rampart --platform-url URL           # Opt-in Platform telemetry
rampart --platform-api-key KEY       # API key for Platform authentication
rampart version                      # Print version
rampart -v                           # Verbose output
```

## API Endpoints (IDE Integration)

IDE extensions call these endpoints — no ML model bundled in extensions:

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/detect` | Scan text: `{"text": "..."}` → detection results |
| `GET` | `/stats` | Proxy statistics: requests, detections, blocked, **mode** |

### Example: Monitor Mode
```bash
curl -s -X POST http://localhost:8080/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "My SSN is 123-45-6789"}'

# HTTP 200 — detection results, traffic still flows
{"total_detections": 3, "blocked": false, "results": [...]}
```

### Example: Block Mode
```bash
curl -s -X POST http://localhost:8080/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "My SSN is 123-45-6789"}'

# HTTP 403 — request blocked
{"blocked": true, "reason": "pii: ssn detected in response",
 "severity": "critical", "results": [...]}
```

### Stats Endpoint
```bash
curl -s http://localhost:8080/stats
{"total_requests": 142, "detections": 23, "blocked_requests": 5,
 "mode": "block", ...}
```

## IDE Coverage

| Editor | Plugin | Type | Status |
|--------|--------|------|--------|
| **JetBrains** (IntelliJ, PyCharm, etc.) | [aegisgate-rampart-jetbrains](https://github.com/aegisgatesecurity/aegisgate-rampart-jetbrains) | Native plugin | ✅ v0.3.0 |
| **VS Code** | [aegisgate-rampart-ext](https://github.com/aegisgatesecurity/aegisgate-rampart-ext) | Extension | ✅ v0.3.0 |
| **Any editor** | LSP server (`rampart-lsp`) | Language Server Protocol | ✅ v0.3.0 |

## Load Testing

Verified with k6: **1.19M requests, 0% crash rate** across 7 test scenarios.

```bash
cd tests/load/k6

# Run individual tests
k6 run stress-test.js          # Baseline (100 VUs)
k6 run break-test.js            # Find ceiling (1,000 VUs)
k6 run crush-test.js            # Survival test (2,000 VUs)
k6 run malformed-input-test.js  # Adversarial input
k6 run connection-flood-test.js  # Connection storms
k6 run endurance-test.js        # 5-min sustained load
k6 run rate-limit-test.js       # Rate limiter verification

# Run all tests
./run-all.sh
```

| Test | Peak VUs | Requests | Crash Rate | Key Result |
|------|----------|----------|------------|------------|
| Stress | 100 | 21K | 0% | p95=210ms |
| Break | 1,000 | 56K | 0% | Survived 1K VUs |
| Crush | 2,000 | 465K | 0% | Survived 2K VUs |
| Malformed | 500 | 25K | 0% | No crash on garbage |
| Connection Flood | 500 | 506K | 0% | Connection storms OK |
| Endurance | 70 | 91K | 0% | 5-min stable |
| Rate Limit | 100 | 27K | 0% | 429s enforced |

## 27 Target Endpoints

Covers all 10 AI providers:

| Provider | API Endpoints | Web Endpoints |
|----------|--------------|---------------|
| OpenAI/ChatGPT | api.openai.com | chat.openai.com, chatgpt.com |
| Anthropic/Claude | api.anthropic.com | claude.ai |
| Gemini | generativelanguage.googleapis.com | gemini.google.com |
| Copilot | api.copilot.microsoft.com | copilot.microsoft.com |
| Perplexity | api.perplexity.ai | perplexity.ai |
| Grok | api.x.ai | grok.com |
| Mistral | api.mistral.ai, codestral.mistral.ai | chat.mistral.ai |
| DeepSeek | api.deepseek.com | chat.deepseek.com |
| Duck.ai | api.duck.ai | duck.ai |
| Meta AI | — | meta.ai |

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

| Product | Surface | Approach | Detection | Block Mode |
|---------|---------|----------|-----------|-------------|
| **Lens** | Browser | DOM blocking (before send) | 154 regex + JS ML | ✅ Block in browser |
| **Rampart** | Desktop, CLI, IDE | HTTPS proxy (in transit) | 153 regex + Go ML | ✅ Block at proxy |
| **Platform** | Server | API gateway | 154 regex + Go ML | ✅ Block at gateway |

**Lens blocks before send. Rampart blocks in transit. Platform blocks at the gateway.** Together = full-spectrum coverage.

## Build & Test

```bash
# Build
CGO_ENABLED=0 go build -o bin/rampart ./cmd/rampart/

# Run all tests with race detector
go test ./... -race -count=1

# Run block mode tests
go test ./pkg/proxy/ -race -run "TestBlock|TestShouldBlock|TestMITMBlock" -v

# Run platform forwarder tests
go test ./internal/platformforward/ -race -v

# Lint
golangci-lint run ./...
```

## Project Structure

```
aegisgate-rampart/
├── cmd/
│   ├── rampart/           # CLI entry point + daemon lifecycle
│   └── rampart-lsp/       # LSP server for any-editor coverage
├── pkg/
│   ├── config/            # Configuration (block mode, 27 endpoints, 12 privacy rules)
│   ├── detector/          # Detection engine wiring
│   ├── proxy/             # HTTPS MITM proxy + /detect + /stats + block mode
│   └── telemetry/         # Platform telemetry (no-op when air-gap)
├── internal/
│   ├── autostart/         # Auto-start (systemd, launchd, Registry)
│   ├── auditlog/          # Audit logging (metadata only, 86.5% coverage)
│   ├── catrust/           # CA trust setup (Linux, macOS, Windows)
│   ├── certificate/       # ECDSA P-256 CA generation
│   ├── certinit/          # First-run certificate setup
│   ├── detectors/         # 153 regex patterns (from Platform v4.0.0)
│   ├── logging/           # Minimal stderr shim
│   ├── lsp/               # Language Server Protocol server (91.5% coverage)
│   ├── ml/                # Char CNN-BiLSTM (ONNX + heuristic fallback)
│   ├── notify/            # Desktop notifications (3 platforms)
│   ├── platform/          # Platform-aware paths (ConfigDir, DataDir, CacheDir)
│   ├── platformforward/   # Platform telemetry forwarding (opt-in, 91.7% coverage)
│   ├── response/          # PII scanner, secret detector, guard (93.8% coverage)
│   └── tray/              # System tray (fyne.io/systray)
├── tests/load/k6/          # k6 load testing suite (7 scenarios)
├── configs/default.json    # Default configuration
├── Dockerfile              # Multi-stage scratch container
└── .github/workflows/      # CI/CD workflows (5 platforms)
```

## License

Apache-2.0