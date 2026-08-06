# AegisGate Rampart

**Secure every AI interaction — beyond the browser.**

Rampart is a local AI security proxy that detects PII, secrets, prompt injection, and compliance violations in AI traffic flowing through desktop apps, CLI tools, IDEs, and any application that makes outbound HTTPS calls to AI API endpoints.

## Architecture

```
                    ┌─────────────┐
                    │   Platform   │ ← telemetry, audit, compliance (optional)
                    │   (optional) │
                    └──────▲───────┘
                           │
                    ┌──────┴───────┐
                    │   Rampart    │ ← local HTTPS proxy + detection engine
                    └──┬───┬───┬──┬─┘
                       │   │   │  │
            ┌──────────┘   │   │  └──────────┐
            │              │              │
     ┌──────┴───┐  ┌──────┴───┐  ┌───────┴────┐
     │  Desktop  │  │   IDE    │  │    CLI     │
     │   Apps    │  │ Extension│  │   Tools    │
     │(Claude,   │  │(VS Code, │  │(aider, llm,│
     │ChatGPT)   │  │Cursor)   │  │Continue)   │
     └──────────┘  └──────────┘  └────────────┘
```

## Key Principles

- **Air-gap ready**: Zero phone-home. All detection runs locally.
- **Same detection engine**: Regex + ML (Char CNN-BiLSTM), ~5ms inference
- **Privacy by design**: 12 privacy non-negotiables enforced in code
- **Single binary**: Go compile, no external dependencies
- **Two modes**: `rampart` (foreground/TUI) and `rampart --daemon` (background/desktop)

## Quick Start

```bash
# Build
go build -o bin/rampart ./cmd/rampart

# Run in foreground (TUI mode)
./bin/rampart

# Run as daemon (desktop mode with notifications)
./bin/rampart --daemon

# One-shot detection (no proxy)
./bin/rampart detect "My SSN is 123-45-6789"

# With Platform telemetry (org mode)
./bin/rampart --platform-url https://platform.yourorg.com
```

## Detection Capabilities

- 151 regex patterns across 5 facets (PII, secrets, XSS, compliance, adversarial ML)
- Char CNN-BiLSTM ML model (~5ms inference, 100/100 evasion resistance)
- 27 compliance frameworks (SOC 2, HIPAA, PCI-DSS, GDPR, NIST, etc.)
- 0% false positive rate on 10,538 benign samples

## License

Apache 2.0. Copyright 2026 AegisGate Security, LLC.
