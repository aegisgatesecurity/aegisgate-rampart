<div align="center">

# 🛡️ AegisGate Rampart

**Local AI security proxy — intercept, detect, block.**

HTTPS MITM proxy · 153 regex patterns + Char CNN-BiLSTM · Monitor & Block modes · Zero telemetry by default

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-v0.6.0-brightgreen.svg)](https://github.com/aegisgatesecurity/aegisgate-rampart/releases/tag/v0.6.0)
[![CI](https://github.com/aegisgatesecurity/aegisgate-rampart/actions/workflows/ci.yml/badge.svg)](https://github.com/aegisgatesecurity/aegisgate-rampart/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-80.7%25-brightgreen.svg)](#test-coverage)
[![Security](https://github.com/aegisgatesecurity/aegisgate-rampart/actions/workflows/security.yml/badge.svg)](https://github.com/aegisgatesecurity/aegisgate-rampart/actions/workflows/security.yml)
[![CodeQL](https://github.com/aegisgatesecurity/aegisgate-rampart/actions/workflows/codeql.yml/badge.svg)](https://github.com/aegisgatesecurity/aegisgate-rampart/actions/workflows/codeql.yml)
[![Tests](https://img.shields.io/badge/tests-88%20files%20%7C%2027%20packages-blue.svg)](#test-coverage)
[![Load Tests](https://img.shields.io/badge/load%20tests-7%20k6%20scenarios-success.svg)](#load-testing)
[![Crash Rate](https://img.shields.io/badge/crash%20rate-0.0000%25-success.svg)](#load-testing)
[![Throughput](https://img.shields.io/badge/throughput-235%20RPS-blue.svg)](#load-testing)
[![Endpoints](https://img.shields.io/badge/endpoints-27%20AI%20APIs-9cf.svg)](#27-target-endpoints)
[![Providers](https://img.shields.io/badge/providers-10-blue.svg)](#27-target-endpoints)
[![Zero npm](https://img.shields.io/badge/dependencies-zero-success.svg)](#build--test)
[![Privacy](https://img.shields.io/badge/privacy-12%20non--negotiables-success.svg)](#privacy-12-non-negotiables)

[Quick Start](#quick-start) · [Operating Modes](#operating-modes) · [Detection](#detection-capabilities) · [IDE Integration](#ide-coverage) · [Privacy](#privacy-12-non-negotiables) · [Releases](https://github.com/aegisgatesecurity/aegisgate-rampart/releases)

</div>

> **We follow [GitHub's recommended security practices](https://securitylab.github.com/resources/five-easy-steps-to-secure-your-open-source-project/) for open source projects.** CodeQL scanning · Secret scanning with push protection · Dependabot alerts & security updates · Protected branches · RFC 9116 security policy · Sigstore keyless signing · [Report a vulnerability →](./SECURITY.md)

---

> **🛡️ Using AegisGate at work?** [AegisGate Platform](https://github.com/aegisgatesecurity/aegisgate-platform) is our server-side gateway — 153 detection patterns, MCP/A2A/ACP protection, 15+ compliance frameworks, and cryptographic attestation. For individual developers, Rampart runs locally on your machine. [Explore Platform →](https://github.com/aegisgatesecurity/aegisgate-platform)

---

## What's New in v0.6.0

- **🛡️ Block Mode** — Actively block threats at the proxy level. Returns HTTP 403 with structured JSON response. Configurable threshold, categories, and block direction (request, response, or both).
- **🧠 ML Adversarial Detection** — Char CNN-BiLSTM with Attention model detects adversarial prompt injections (instruction override, roleplay injection, obfuscated commands) in real time.
- **🔐 Encrypted Audit Logs** — ChaCha20-Poly1305 authenticated encryption with PBKDF2-SHA256 key derivation. Key is never stored — decryption requires original passphrase.
- **📊 Anonymized Metrics** — Opt-in privacy-preserving telemetry. Domain hashed with SHA-256, timestamps rounded to hour, only false positives reported.
- **🔔 Webhook Notifications** — Configurable webhook integration for detection alerts. Custom headers, multiple endpoints.
- **📦 Enterprise Features** — Config hash verification, cosign signing support, self-hosted LLM configuration, batch scanning.
- **✅ 80.7% test coverage** (88 test files, 27 packages, 7 k6 load tests, 0.0000% crash rate at 2,000+ concurrent users).

## What Is Rampart?

Rampart is a **local HTTPS MITM proxy** that sits between your applications and AI API endpoints. It intercepts traffic in transit, runs real-time detection for PII, secrets, XSS, compliance violations, and adversarial prompt injections — and can **actively block** threats before they reach the AI service.

- **In-transit interception.** Unlike Lens (browser-level) or Platform (gateway-level), Rampart operates at the network proxy layer — it sees every request and response.
- **153 regex patterns + ML.** Same detection engine as AegisGate Platform v4.0.0. Regex catches known patterns; Char CNN-BiLSTM catches adversarial paraphrasing.
- **Monitor or Block.** Log-only mode for visibility. Block mode for enforcement with configurable thresholds and categories.
- **Zero telemetry by default.** Air-gap mode when `--platform-url` is not set. No network calls. All detection is local.
- **Free. Forever.** Apache 2.0, single binary, no external dependencies.

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

## Platform Support

| Platform | Config Directory | Auto-Start | Notifications | CA Trust | System Tray |
|----------|-----------------|-------------|-------------|----------|-------------|
| **Linux** | `~/.config/aegisgate-rampart/` | systemd | notify-send | update-ca-certificates | fyne/systray (CGO) |
| **macOS** | `~/Library/Application Support/aegisgate-rampart/` | launchd | osascript | security add-trusted-cert | fyne/systray (CGO) |
| **Windows** | `%AppData%\AegisGate Rampart\` | Registry Run key | beeep (Win32 toast) | certutil -addstore | fyne/systray |

**Build requirements**: Linux and Windows build with `CGO_ENABLED=0`. macOS requires `CGO_ENABLED=1` (systray uses Objective-C).

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

## Test Coverage

| Metric | Value |
|--------|-------|
| Test files | 88 |
| Packages tested | 27 |
| Filtered coverage | 80.7% |
| Load test scenarios | 7 (k6) |
| Crash rate | 0.0000% |
| Peak concurrent users | 2,000+ |

See full results in the v0.6.0 release notes.

## Load Testing

**v0.6.0 Results:** 235 RPS throughput, p95=201ms latency, **0.0000% crash rate** across 7 test scenarios.

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

### Enhanced Privacy Features (v0.5.1)

**Audit Log Encryption (P2#11):**
- Encrypt audit logs at rest with **ChaCha20-Poly1305** authenticated encryption
- Key derived from passphrase via **PBKDF2-SHA256** (100K iterations)
- Key is **NEVER stored** - decryption requires original passphrase
- Protects against disk theft and forensic analysis

```bash
# Generate secure passphrase
rampart generate-passphrase

# Enable encrypted audit logging
rampart --audit-key-passphrase="your-passphrase"

# Decrypt logs later
rampart decrypt-audit --audit-key-passphrase="your-passphrase" audit.log.enc output.log
```

**Anonymized Metrics (P2#12):**
- **Opt-in only** - disabled by default
- Domain hashed with **SHA-256** → 16 hex chars (cannot reverse)
- Timestamps rounded to hour (cannot correlate events)
- Only **false positives** sent (user-confirmed)
- No identifiers, no content, no PII

```bash
# Enable privacy-preserving telemetry
rampart --anonymized-metrics
```

See **[PRIVACY.md](PRIVACY.md)** for complete privacy documentation.

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
│   ├── auditlog/          # Audit logging (metadata only, encrypted at rest)
│   ├── catrust/           # CA trust setup (Linux, macOS, Windows)
│   ├── certificate/       # ECDSA P-256 CA generation
│   ├── certinit/          # First-run certificate setup
│   ├── detectors/         # 153 regex patterns (from Platform v4.0.0)
│   ├── enterprise/        # Enterprise features (config hash, verify, gate)
│   ├── logging/           # Minimal stderr shim
│   ├── lsp/               # Language Server Protocol server
│   ├── ml/                # Char CNN-BiLSTM (ONNX + heuristic fallback)
│   ├── notify/            # Desktop notifications (3 platforms)
│   ├── platform/          # Platform-aware paths (ConfigDir, DataDir, CacheDir)
│   ├── platformforward/   # Platform telemetry forwarding (opt-in)
│   ├── response/          # PII scanner, secret detector, guard
│   ├── scanner/           # Batch scanning
│   ├── securemem/         # Secure memory handling
│   ├── tray/              # System tray (fyne.io/systray)
│   ├── updater/           # Self-update mechanism
│   ├── verify/            # Cosign verification
│   └── webhook/           # Webhook notification manager
├── tests/load/k6/          # k6 load testing suite (7 scenarios)
├── configs/default.json    # Default configuration
├── Dockerfile              # Multi-stage scratch container
└── .github/workflows/      # CI/CD workflows
```

## License

Apache-2.0. See [LICENSE](./LICENSE) for the full text.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

<div align="center">

[🌐 AegisGate Security](https://aegisgatesecurity.io) · [✉️ support@aegisgatesecurity.io](mailto:support@aegisgatesecurity.io) · [𝕏 @aegisgate](https://x.com/aegisgate) · [🐘 @aegisgate@mastodon.social](https://mastodon.social/@aegisgate)

Made with 🖤 by AegisGate Security developers to secure the AI attack surface.

</div>