<div align="center">

# 🛡️ AegisGate Rampart

**Local firewall for AI coding tools — intercept, detect, block.**

*A free local proxy that sits between your editor and the AI model, catching secrets and sensitive data before they leave your machine.*

HTTPS MITM proxy · 176 regex patterns + Char CNN-BiLSTM · Monitor & Block modes · Zero telemetry by default

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-v0.7.0-brightgreen.svg)](https://github.com/aegisgatesecurity/aegisgate-rampart/releases/tag/v0.7.0)
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

> **🛡️ Using AegisGate at work?** [AegisGate Platform](https://github.com/aegisgatesecurity/aegisgate-platform) is our server-side gateway — 176 detection patterns, MCP/A2A/ACP protection, 31 compliance frameworks, and cryptographic attestation. For individual developers, Rampart runs locally on your machine. [Explore Platform →](https://github.com/aegisgatesecurity/aegisgate-platform)

---

## What is Rampart?

Rampart is a **local security tool for developers** who use AI coding assistants like GitHub Copilot, Cursor, or local LLMs (Ollama, LM Studio). It sits between your editor and the AI model, scanning everything you send — and everything the AI sends back — for sensitive data and security risks.

Think of it as a firewall for AI coding tools. It catches the moment you're about to send a database password to Copilot, or when the AI generates code that contains an API key, and stops it before it's too late.

- **In-transit interception.** Unlike Lens (browser-level) or Platform (gateway-level), Rampart operates at the network proxy layer — it sees every request and response.
- **176 regex patterns + ML.** Same detection engine as AegisGate Platform. Regex catches known patterns; Char CNN-BiLSTM catches adversarial paraphrasing.
- **Monitor or Block.** Log-only mode for visibility. Block mode for enforcement with configurable thresholds and categories.
- **Zero telemetry by default.** Air-gap mode when `--platform-url` is not set. No network calls. All detection is local.
- **Free. Forever.** Apache 2.0, single binary, no external dependencies.

## Do I need Rampart?

**If you use AI chat in a browser (ChatGPT, Claude, etc.):** You need [Lens](https://github.com/aegisgatesecurity/aegisgate-lens) — it's a free browser extension that protects you in the browser. Rampart is not for this use case.

**If you use AI coding tools (Copilot, Cursor, local LLMs, API calls):** You need Rampart. It protects the places Lens can't reach — your IDE, your terminal, your API calls.

| Your setup | What to use |
|-----------|-------------|
| ChatGPT or Claude in a browser | [Lens](https://github.com/aegisgatesecurity/aegisgate-lens) (free browser extension) |
| GitHub Copilot in VS Code | **Rampart** (IDE plugin) |
| Cursor AI editor | **Rampart** (IDE plugin) |
| Local LLMs (Ollama, LM Studio) | **Rampart** (local proxy) |
| API calls to OpenAI/Anthropic from your code | **Rampart** (local proxy) |
| Both browser chat AND coding tools | **Lens + Rampart** (both are free) |

## What does it catch?

| Risk | Examples |
|------|----------|
| **Secrets** | API keys (AWS, GitHub, OpenAI, Stripe), database passwords, SSH private keys, JWT tokens, OAuth tokens |
| **Personal info (PII)** | SSN, email, phone, credit card, passport, bank routing numbers |
| **Prompt injection** | Adversarial prompts designed to make the AI ignore safety rules, leak system prompts, or execute unauthorized actions |
| **Compliance violations** | Text that violates HIPAA, GDPR, PCI-DSS, EU AI Act |
| **Malicious code (XSS)** | Script injection, event handlers, encoded payloads, SVG vectors |
| **Response risks** | PII leaked in AI responses, hallucinated secrets, injected content in model output |

## Quick Start

### Option 1: Install the IDE plugin (recommended)

**VS Code / Cursor:**
1. Open the Extensions panel (`Ctrl+Shift+X` / `Cmd+Shift+X`)
2. Search for "AegisGate Rampart"
3. Click Install, then Reload
4. Detection runs automatically as you type — results appear as inline warnings

**JetBrains (IntelliJ, PyCharm, WebStorm, etc.):**
1. Open Settings → Plugins → Marketplace
2. Search for "AegisGate Rampart"
3. Click Install, then Restart
4. Detection results appear in the Problems tool window

**Neovim / any LSP editor:**
```bash
# Download the Rampart LSP binary
curl -L https://github.com/aegisgatesecurity/aegisgate-rampart/releases/latest/download/rampart-lsp-linux-amd64 -o /usr/local/bin/rampart-lsp
chmod +x /usr/local/bin/rampart-lsp

# Add to your LSP config (Neovim example)
# lspconfig.rampart_lsp.setup({})
```

### Option 2: Run as a local proxy

```bash
# Build
CGO_ENABLED=0 go build -o bin/rampart ./cmd/rampart

# Monitor mode (default) — log only
./bin/rampart

# Block mode — actively block PII, secrets, XSS
./bin/rampart --block

# Install CA cert (required for HTTPS interception)
./bin/rampart --trust

# Custom port + block mode + rate limiting
./bin/rampart --port 9090 --block --rate-limit=10000
```

### Option 3: Docker

```bash
docker run -d \
  -p 8443:8443 \
  -p 9090:9090 \
  ghcr.io/aegisgatesecurity/aegisgate-rampart:v0.6.2
```

<details>
<summary><strong>⚙️ Additional CLI Options</strong></summary>

```bash
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

</details>

## What It Does

```
Your Machine                                          AI APIs
┌─────────────────────────────────────────────────────────────────┐
│  Claude Desktop ─┐                                              │
│  ChatGPT App ────┤     ┌──────────────────────┐               │
│  VS Code + Ext ──┼────▶│      RAMPART         │──────▶  api.openai.com
│  CLI (curl) ─────┤     │    :8080 proxy        │──────▶  api.anthropic.com
│  Docker ─────────┘     │                       │──────▶  api.deepseek.com
│                        │ 176 regex patterns    │──────▶  ...24 more
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

## Operating Modes

| Mode | Flag | Behavior | Use Case |
|------|------|----------|----------|
| **Monitor** | _(default)_ | Log & alert, allow all traffic | Developer visibility |
| **Block** | `--block` | Log, alert, **actively block threats** | Security enforcement |

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

<details>
<summary><strong>⚙️ Block Mode Configuration</strong></summary>

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

</details>

## Detection Capabilities

| Category | Patterns | Detects |
|----------|----------|---------|
| **Secrets** | 45 | AWS keys, GitHub tokens, OAuth, JWT, database URLs |
| **PII (US Core)** | 26 | SSN, email, phone, DOB, name, CPT/HCPCS |
| **PII (US Extended)** | 13 | Driver license, passport, medical record |
| **PII (Financial)** | 12 | Credit card (Luhn validated), bank account, SWIFT/BIC |
| **PII (International)** | 24 | National IDs for 15 countries |
| **XSS** | 12 | Script injection, event handlers, data URIs |
| **Compliance** | 35 | GDPR, HIPAA, PCI-DSS, SOX identifiers |
| **OT/ICS Protocols** | 9 | Modbus, DNP3, OPC-UA |
| **ML (Neural)** | 1 model | Char CNN-BiLSTM adversarial prompt detection |

## IDE Coverage

| Editor | Plugin | Type | Status |
|--------|--------|------|--------|
| **JetBrains** (IntelliJ, PyCharm, etc.) | [aegisgate-rampart-jetbrains](https://github.com/aegisgatesecurity/aegisgate-rampart-jetbrains) | Native plugin | ✅ v0.3.0 |
| **VS Code** | [aegisgate-rampart-ext](https://github.com/aegisgatesecurity/aegisgate-rampart-ext) | Extension | ✅ v0.3.0 |
| **Any editor** | LSP server (`rampart-lsp`) | Language Server Protocol | ✅ v0.3.0 |

## Platform Support

| Platform | Config Directory | Auto-Start | Notifications | CA Trust | System Tray |
|----------|-----------------|-------------|-------------|----------|-------------|
| **Linux** | `~/.config/aegisgate-rampart/` | systemd | notify-send | update-ca-certificates | fyne/systray (CGO) |
| **macOS** | `~/Library/Application Support/aegisgate-rampart/` | launchd | osascript | security add-trusted-cert | fyne/systray (CGO) |
| **Windows** | `%AppData%\AegisGate Rampart\` | Registry Run key | beeep (Win32 toast) | certutil -addstore | fyne/systray |

**Build requirements**: Linux and Windows build with `CGO_ENABLED=0`. macOS requires `CGO_ENABLED=1` (systray uses Objective-C).

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

<details>
<summary><strong>🔐 Enhanced Privacy Features (v0.5.1+)</strong></summary>

**Audit Log Encryption:**
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

**Anonymized Metrics:**
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

</details>

## Product Family

| Product | Surface | Approach | Detection | Block Mode |
|---------|---------|----------|-----------|-------------|
| **Lens** | Browser | DOM blocking (before send) | 155 regex + JS ML | ✅ Block in browser |
| **Rampart** | Desktop, CLI, IDE | HTTPS proxy (in transit) | 176 regex + Go ML | ✅ Block at proxy |
| **Platform** | Server | API gateway | 176 regex + Go ML | ✅ Block at gateway |

**Lens blocks before send. Rampart blocks in transit. Platform blocks at the gateway.** Together = full-spectrum coverage.

<details>
<summary><strong>📦 What's New in v0.6.2</strong></summary>

- **🔒 23 New SOC Detection Patterns** — SWIFT/BIC banking codes (3 patterns), CPT/HCPCS medical billing codes (11 patterns), and OT/ICS protocol patterns (9 patterns: Modbus, DNP3, OPC-UA). Parity with Platform v4.1.0 and Lens v0.3.1.
- **🔧 Go 1.26.6** — Runtime bump from Go 1.25.0, fixes 5 stdlib vulnerabilities.
- **🧪 Test coverage** — 88 test files, 27 packages, all passing with `-race`.

</details>

<details>
<summary><strong>📦 What's New in v0.6.0</strong></summary>

- **🛡️ Block Mode** — Actively block threats at the proxy level. Returns HTTP 403 with structured JSON response. Configurable threshold, categories, and block direction (request, response, or both).
- **🧠 ML Adversarial Detection** — Char CNN-BiLSTM with Attention model detects adversarial prompt injections (instruction override, roleplay injection, obfuscated commands) in real time.
- **🔐 Encrypted Audit Logs** — ChaCha20-Poly1305 authenticated encryption with PBKDF2-SHA256 key derivation. Key is never stored — decryption requires original passphrase.
- **📊 Anonymized Metrics** — Opt-in privacy-preserving telemetry. Domain hashed with SHA-256, timestamps rounded to hour, only false positives reported.
- **🔔 Webhook Notifications** — Configurable webhook integration for detection alerts. Custom headers, multiple endpoints.
- **📦 Enterprise Features** — Config hash verification, cosign signing support, self-hosted LLM configuration, batch scanning.
- **✅ 80.7% test coverage** (88 test files, 27 packages, 7 k6 load tests, 0.0000% crash rate at 2,000+ concurrent users).

</details>

## Test Coverage

| Metric | Value |
|--------|-------|
| Test files | 88 |
| Packages tested | 27 |
| Filtered coverage | 80.7% |
| Load test scenarios | 7 (k6) |
| Crash rate | 0.0000% |
| Peak concurrent users | 2,000+ |

<details>
<summary><strong>🧪 Load Testing Details</strong></summary>

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

</details>

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

<details>
<summary><strong>🏗️ Project Structure</strong></summary>

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
│   ├── detectors/         # 176 regex patterns (from Platform v4.1.0)
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

</details>

## License

Apache-2.0. See [LICENSE](./LICENSE) for the full text.

The trained ML model weights are separately licensed under the [AegisGate Model Weight License](WEIGHTS-LICENSE.md). Non-commercial use is permitted; commercial use requires a commercial license.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

<div align="center">

[🌐 AegisGate Security](https://aegisgatesecurity.io) · [✉️ support@aegisgatesecurity.io](mailto:support@aegisgatesecurity.io) · [𝕏 @aegisgate](https://x.com/aegisgate) · [🐘 @aegisgate@mastodon.social](https://mastodon.social/@aegisgate)

Made with 🖤 by AegisGate Security developers to secure the AI attack surface.

</div>