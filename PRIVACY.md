# Privacy Policy

## Privacy by Design

AegisGate Rampart is built with privacy as a fundamental principle, not an afterthought. We believe you should have complete control over your data, especially when using AI security tools.

## Our Privacy Commitment

**Rampart follows 12 non-negotiable privacy principles:**

1. ✅ **No prompt text stored** - Your actual prompts are never persisted
2. ✅ **No PII values stored** - Personal information is redacted before logging
3. ✅ **No secret values stored** - Credentials are masked (e.g., `[REDACTED]`)
4. ✅ **No URLs stored** - Full request URLs are not persisted
5. ✅ **No telemetry by default** - Zero data sent without explicit opt-in
6. ✅ **Local-first processing** - All detection happens on your machine
7. ✅ **Transparent operation** - Open source code you can audit
8. ✅ **Minimal data collection** - Only metadata, never content
9. ✅ **User control** - You decide what, if anything, is shared
10. ✅ **Privacy-preserving analytics** - Hashed, anonymized, aggregated
11. ✅ **No user identification** - No fingerprints, sessions, or IDs
12. ✅ **No third-party sharing** - Your data stays yours

---

## Data Collection

### What Rampart Collects (By Default)

**Audit Logs (Local Only):**
- Detection metadata (category, severity, rule matched)
- Request direction (request/response)
- Host domain (e.g., `api.openai.com`)
- Request path (e.g., `/v1/chat/completions`)
- Timestamp
- Block status
- Redaction status

**What is NEVER Collected:**
- ❌ Prompt text or conversation content
- ❌ PII values (SSN, credit cards, etc.)
- ❌ Secret values (API keys, passwords, tokens)
- ❌ Full URLs with query parameters
- ❌ User identifiers
- ❌ IP addresses
- ❌ Session IDs
- ❌ Browser fingerprints
- ❌ Machine identifiers

### Audit Log Encryption (P2#11)

Rampart supports **encrypted audit logs** for enhanced security:

**How It Works:**
- Enable with `--audit-key-passphrase="your-passphrase"` flag
- Audit logs encrypted with **ChaCha20-Poly1305** (authenticated encryption)
- Encryption key derived from passphrase via **PBKDF2-SHA256** (100,000 iterations)
- **Key is NEVER stored** - derived on-the-fly from your passphrase
- Each entry has unique random nonce (96 bits)
- Random salt generated per logger session (16 bytes)

**Security Guarantees:**
- ✅ Encrypted logs are unreadable without passphrase
- ✅ Protects against disk theft or forensic analysis
- ✅ Key derivation uses OWASP 2026 recommendations
- ✅ Authenticated encryption prevents tampering

**Decryption:**
```bash
# Decrypt audit logs (requires original passphrase)
rampart decrypt-audit --audit-key-passphrase="your-passphrase" audit.log.enc decrypted.log
```

**⚠️ Critical:** If you lose your passphrase, encrypted logs **CANNOT be recovered**. Store your passphrase in a secure password manager.

---

## Anonymized Metrics (P2#12)

Rampart includes **opt-in, privacy-preserving telemetry** to help improve the product.

### What is NEVER Sent

- ❌ Full domain names (only hashed)
- ❌ Exact timestamps (rounded to hour)
- ❌ Prompt text
- ❌ PII values
- ❌ Secret values
- ❌ User identifiers
- ❌ IP addresses
- ❌ Session IDs
- ❌ Browser fingerprints
- ❌ Machine identifiers

### What IS Sent (When Opted-In)

**Anonymized Metric Fields:**
```json
{
  "rampart_version": "0.6.2",
  "platform": "linux-amd64",
  "domain_hash": "a3f2c8d91e4b5f67",  // 16 hex chars (can't reverse)
  "category": "pii_ssn",
  "severity": "critical",
  "blocked": true,
  "hour": "2026-08-08T13:00:00Z",  // Rounded to hour
  "false_positive": true,  // Only if user-confirmed
  "user_action": "confirmed_false_positive"
}
```

### Privacy Guarantees

**Domain Hashing:**
- Algorithm: **SHA-256**
- Output: **16 hexadecimal characters** (64 bits)
- Normalization: lowercase, strip port, strip `www.` prefix
- **Cannot be reversed** to recover original domain
- Consistent: same domain always produces same hash

**Example:**
```
api.openai.com        → "a3f2c8d91e4b5f67"
API.OPENAI.COM        → "a3f2c8d91e4b5f67"  (case-insensitive)
www.api.openai.com    → "a3f2c8d91e4b5f67"  (www. stripped)
api.openai.com:443    → "a3f2c8d91e4b5f67"  (port stripped)
```

**Timestamp Rounding:**
- All timestamps rounded to **hour boundary**
- Prevents correlation of events
- Example: `13:47:23` → `13:00:00`

**False Positives Only:**
- Only false positive detections are sent (user-confirmed)
- Helps improve detection accuracy
- Includes user action taken (e.g., "confirmed_false_positive")

### How to Enable

**Opt-in only** - disabled by default:

```bash
# Enable anonymized metrics
rampart --anonymized-metrics

# Enable with custom endpoint
rampart --anonymized-metrics --metrics-endpoint="https://custom.example.com/metrics"
```

**Collection Endpoint:**
- Default: `https://rampart.aegisgatesecurity.io/metrics`
- Batched: 10 metrics per batch (or 5-minute timeout)
- Async: Non-blocking, won't slow down detections

---

## Platform Integration (Optional)

Rampart can optionally forward detection metadata to AegisGate Platform for centralized monitoring.

**What is Forwarded (when configured):**
- Detection metadata (category, severity, rule)
- Redacted values (PII masked, secrets redacted)
- Host domain
- Timestamp

**What is NEVER Forwarded:**
- ❌ Prompt text
- ❌ Full PII values
- ❌ Secret values
- ❌ User identifiers

**Enable Platform Forwarding:**
```bash
rampart --platform-url="https://platform.example.com" --platform-api-key="your-key"
```

---

## Data Storage

### Local Storage Locations

| Data Type | Location | Encryption |
|-----------|----------|------------|
| CA Certificate | `~/.config/aegisgate-rampart/ca.crt` | No (public) |
| CA Private Key | `~/.config/aegisgate-rampart/ca.key` | No (0600 permissions) |
| Audit Log (unencrypted) | `~/.local/share/aegisgate-rampart/audit.log` | No |
| Audit Log (encrypted) | `~/.local/share/aegisgate-rampart/audit.log.enc` | ✅ Yes (ChaCha20-Poly1305) |
| Configuration | `~/.config/aegisgate-rampart/config.json` | No |

### Data Retention

**Audit Logs:**
- Unencrypted: Retained indefinitely (user-managed)
- Encrypted: Retained indefinitely (user-managed)
- User responsibility: Implement log rotation and retention policies

**Anonymized Metrics:**
- Not stored locally (sent to collection endpoint)
- Retention policy: See AegisGate data retention policy

---

## User Rights

You have complete control over your data:

1. **Right to Access**: All data is stored locally in readable formats
2. **Right to Delete**: Delete any files in your config/data directories
3. **Right to Portability**: Export audit logs in JSONL format
4. **Right to Opt-Out**: Disable metrics with `--anonymized-metrics=false`
5. **Right to Encryption**: Encrypt audit logs with `--audit-key-passphrase`

---

## Third-Party Services

Rampart uses the following third-party services (only when explicitly configured):

| Service | Purpose | Data Shared |
|---------|---------|-------------|
| AegisGate Platform | Centralized monitoring | Detection metadata (redacted) |
| Anonymized Metrics | Product improvement | Hashed domains, rounded timestamps |

**No data is sent to any third party by default.**

---

## Security Measures

We implement industry-standard security practices:

- **Encryption at Rest**: Audit logs can be encrypted with ChaCha20-Poly1305
- **Encryption in Transit**: HTTPS for all external communications
- **Access Controls**: CA private key uses 0600 permissions
- **Minimal Data**: Only essential metadata collected
- **Anonymization**: Domains hashed, timestamps rounded
- **Open Source**: Code auditable under Apache 2.0 license

---

## Compliance

Rampart is designed to help users comply with privacy regulations:

- **GDPR**: Data minimization, user control, no personal data sent by default
- **CCPA**: Opt-in telemetry, user rights to access/delete
- **HIPAA**: No PHI stored or transmitted (when configured properly)
- **SOC 2**: Privacy controls built into architecture

**Note:** Compliance depends on proper configuration and usage. Consult your legal/compliance team for specific requirements.

---

## Changes to This Policy

We may update this privacy policy as features evolve. Changes will be documented in:

- GitHub releases: https://github.com/aegisgatesecurity/aegisgate-rampart/releases
- CHANGELOG.md in the repository

**Material changes** will be announced via:
- GitHub release notes
- Security advisories (if applicable)

---

## Contact

**Privacy Questions:** privacy@aegisgatesecurity.io

**Security Issues:** security@aegisgatesecurity.io (see SECURITY.md)

**General Inquiries:** info@aegisgatesecurity.io

---

**Last updated**: August 17, 2026  
**Version**: 1.1 (v0.6.2 release)
