# AegisGate Rampart — Threat Model

## Overview

Rampart is a local HTTPS MITM proxy that inspects AI API traffic for PII, secrets, XSS, and compliance violations. This document describes what Rampart protects against, what it does NOT protect against, and the trust boundaries.

## Trust Boundaries

- **Inside Trust Boundary**: Rampart process, local config, CA private key, audit logs
- **Outside Trust Boundary**: AI API endpoints, network traffic, local disk (other processes), other local users

## Assets Protected

- PII in AI prompts/responses (SSN, credit cards, etc.)
- API keys and secrets in AI prompts/responses
- Prompt injection attempts, XSS vectors, compliance violations

## Threats Addressed

| Threat | Mitigation | Confidence |
|--------|-----------|------------|
| PII leakage via AI prompts | Regex + ML detection, block mode | High |
| Secret/API key exposure | 153 regex patterns, block mode | High |
| XSS via AI responses | Pattern detection, block mode | Medium |
| Compliance violations | 35 compliance patterns across 8+ frameworks | Medium |
| Prompt injection | OWASP LLM patterns + ML threat detection | Medium |

## Threats NOT Addressed (Out of Scope)

| Threat | Why |
|--------|-----|
| Network-level attacks | Rampart is not a firewall or IDS |
| Authentication/authorization | Rampart does not manage user identity |
| AI model safety | Rampart detects, doesn't modify, model behavior |
| Encrypted traffic outside supported endpoints | Only configured AI API endpoints are intercepted |
| Local privilege escalation | Rampart assumes the local OS is trusted |

## Threats TO Rampart

| Threat | Impact | Mitigation |
|--------|--------|-----------|
| CA private key theft | Attacker can intercept ALL HTTPS traffic | 0600 file permissions, recommend FIM |
| Config tampering (block→monitor) | Silent security downgrade | Recommend FIM, future: config hash verification |
| Detection engine DoS | CPU exhaustion via crafted input | Rate limiting, request size limits |
| Audit log tampering | Loss of forensic evidence | Append-only log, recommend FIM |
| Binary supply chain attack | Compromised Rampart binary | Cosign/Sigstore signing, SBOMs in releases |
| ReDoS on regex patterns | CPU exhaustion on crafted input | RE2-compliant regex (no lookbehind/lookahead), future: input size limits |

## Security Assumptions

1. The local machine is not compromised (if it is, game over)
2. The user running Rampart is authorized to intercept HTTPS traffic
3. The CA private key is stored securely (0600 permissions)
4. The audit log directory is protected from unauthorized access
5. The ONNX model file is not tampered with (future: integrity check)

## Reporting

See SECURITY.md for vulnerability reporting procedures.