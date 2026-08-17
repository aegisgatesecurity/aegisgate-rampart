# Security Policy

## Supported Versions

AegisGate Rampart follows semantic versioning. We are currently pre-1.0, so all 0.x.x versions receive security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Security Architecture

Rampart is designed with security as a first principle:

- **Air-gap ready**: Zero phone-home when `PlatformURL` is empty
- **Local-first**: All detection logic runs locally on your machine
- **Transparent proxy**: MITM certificates are generated locally and never transmitted
- **Open source**: All code is auditable under Apache 2.0 license

### Audit Log Data Handling

Rampart audit logs store detection metadata including categories, matched rules, and severity levels. **The original prompt text, PII values, and secret values are never stored in audit logs.** Secret values are redacted to `[REDACTED]` and PII values are partially masked (e.g., `SSN: ***-**-1234`) before any logging occurs.

### Audit Log Encryption (P2#11)

Rampart supports **encrypted audit logs** for enhanced security against disk theft and forensic analysis:

**Encryption Specifications:**
- Algorithm: **ChaCha20-Poly1305** (IETF variant, authenticated encryption)
- Key Size: **256 bits**
- Nonce: **96 bits** (random per entry)
- Authentication Tag: **128 bits**
- Key Derivation: **PBKDF2-SHA256** (100,000 iterations, OWASP 2026 recommendation)
- Salt: **16 bytes** (random per logger session)

**Enable Encryption:**
```bash
# Generate secure passphrase
rampart generate-passphrase

# Start proxy with encrypted audit logging
rampart --audit-key-passphrase="your-secure-passphrase"
```

**Security Guarantees:**
- ✅ Encryption key is **NEVER stored** on disk
- ✅ Key derived from passphrase on-the-fly
- ✅ Decryption requires exact original passphrase
- ✅ Protects against disk theft, forensic analysis, unauthorized access
- ✅ Authenticated encryption prevents tampering

**⚠️ Critical:** If you lose your passphrase, encrypted logs **CANNOT be recovered**. Store passphrases in a secure password manager.

**Decrypt Audit Logs:**
```bash
rampart decrypt-audit --audit-key-passphrase="your-passphrase" audit.log.enc decrypted.log
```

**Storage:**
- Unencrypted: `~/.local/share/aegisgate-rampart/audit.log`
- Encrypted: `~/.local/share/aegisgate-rampart/audit.log.enc`

### CA Private Key Security

The CA private key is stored on disk with **0600 file permissions** (owner read/write only). It should be protected with file integrity monitoring (FIM). **If the CA private key is compromised, an attacker could intercept all HTTPS traffic** passing through the proxy. If compromise is suspected, immediately rotate the CA key and re-install the new CA certificate on all client machines.

### Block Mode Security

In block mode, blocked request metadata (category, rule, severity) is logged, but the **original request content is not persisted**. The blocking response is only visible to the proxy operator, not the downstream AI API endpoint.

### Config Integrity

Rampart includes **config file integrity verification** to detect unauthorized modifications:

**Features:**
- SHA-256 hash verification of config files
- Detects silent downgrades (e.g., `block` → `monitor` mode)
- Tamper detection for any config changes
- Hash record storage with timestamps

**Generate Hash Record:**
```bash
# Generate hash for config file
rampart config-hash ~/.config/aegisgate-rampart/config.json --output config-hashes.json

# With comment for versioning
rampart config-hash config.json --comment "Production config v0.6.1"
```

**Verify Config Integrity:**
```bash
# Verify against stored hash record
rampart config-verify config.json --hash-record config-hashes.json

# Verify with change detection
rampart config-check --hash-record config-hashes.json
```

**Exit Codes:**
- `0` - Config integrity verified
- `1` - Integrity check failed (hash mismatch)
- `2` - Error (file not found, invalid format)

**Best Practices:**
1. Generate hash record after initial config setup
2. Store hash record separately from config (different directory, different permissions)
3. Verify config integrity on startup (automated via systemd/launchd)
4. Alert on hash mismatch (potential tampering)
5. Re-generate hash after authorized config changes

### Memory Security Limitations (P2#10)

**Current State:** Rampart v0.6.1 does not implement secure memory zeroing for passphrases and secrets. This is a **known limitation** planned for v0.7.0.

**Risk:** Sensitive data (CA key passphrases, audit log encryption passphrases, API keys) may persist in RAM after use and could potentially be recovered through:
- Memory dumps (core files)
- Swap/page files
- Hibernation files
- Forensic memory analysis
- Cold boot attacks (requires physical access)

**Why This Is Hard in Go:**
1. **Garbage collector** - Go's GC copies memory freely; you can't control object lifecycle
2. **Compiler optimizations** - "Dead store" elimination may remove zeroing code
3. **Multiple copies** - Strings, function parameters, and slices create copies in memory
4. **No secure primitives** - Go stdlib lacks `mlock()`, secure heap, or protected memory
5. **Runtime copies** - Stack growth, escape analysis, and GC compaction all copy memory

**Mitigations (Recommended for Production):**

1. **Disable core dumps:**
   ```bash
   # Systemd service (recommended)
   [Service]
   LimitCORE=0
   
   # Shell (temporary)
   ulimit -c 0
   ```

2. **Disable or encrypt swap:**
   ```bash
   # Disable swap (requires reboot or root)
   sudo swapoff -a
   
   # OR use encrypted swap (Linux)
   # Configure in /etc/crypttab
   ```

3. **Disable hibernation:**
   ```bash
   sudo systemctl mask systemd-hibernate.service
   ```

4. **Use full-disk encryption:**
   - LUKS (Linux)
   - FileVault (macOS)
   - BitLocker (Windows)

5. **Restart Rampart periodically:**
   - Clears RAM contents
   - Recommended for long-running deployments

6. **Minimize secret lifetime:**
   - Pass passphrases via CLI flags (not config files)
   - Use environment variables (cleared on process exit)
   - Avoid logging secrets (already enforced)

**Enterprise Users:** Consider implementing memory protection at the OS/hardware level:
- Intel SGX (Software Guard Extensions)
- AMD SEV (Secure Encrypted Virtualization)
- ARM TrustZone
- Secure enclaves

**Future Plans (v0.7.0):**
- Evaluate `memguard` library for memory locking
- Implement secure byte buffers with automatic zeroing
- Use Go 1.22+ `runtime/volatile` for guaranteed writes
- Minimize copies (pass pointers, use `[]byte` not `string`)
- Document remaining limitations transparently

**Threat Model:** Memory dump attacks require:
- Physical access to machine, OR
- Root/administrator access, OR
- System crash with core dumps enabled

These are **less common** than disk theft or config tampering (which ARE protected in v0.6.1).

**Status:** ⏳ Deferred to v0.7.0 for proper implementation. v0.6.1 is production-ready with OS-level mitigations.

### Anonymized Metrics (P2#12)

Rampart includes **opt-in, privacy-preserving telemetry** for product improvement:

**Privacy Guarantees:**
- ✅ **Opt-in only** - disabled by default
- ✅ **Domain hashing** - SHA-256 → 16 hex chars (cannot reverse)
- ✅ **Timestamp rounding** - to hour boundary (cannot correlate events)
- ✅ **No identifiers** - no IPs, sessions, fingerprints, or user IDs
- ✅ **No content** - no prompt text, PII values, or secrets
- ✅ **False positives only** - only user-confirmed false positives sent

**Enable Metrics:**
```bash
rampart --anonymized-metrics
```

**Collection Endpoint:**
- Default: `https://rampart.aegisgatesecurity.io/metrics`
- Custom: `--metrics-endpoint="https://custom.example.com/metrics"`

**What IS Sent:**
- Rampart version (e.g., "0.5.0")
- Platform (e.g., "linux-amd64")
- Hashed domain (16 hex chars)
- Detection category (e.g., "pii_ssn")
- Severity (low/medium/high/critical)
- Blocked status (true/false)
- Hour timestamp (rounded)
- False positive flag (if user-confirmed)
- User action (for false positives only)

**What is NEVER Sent:**
- ❌ Full domain names
- ❌ Exact timestamps
- ❌ Prompt text
- ❌ PII values
- ❌ Secret values
- ❌ User identifiers
- ❌ IP addresses
- ❌ Session IDs

See **PRIVACY.md** for complete details.

## Reporting a Vulnerability

We take the security of Rampart seriously. If you believe you've found a security vulnerability, please report it responsibly.

### How to Report

**Email**: security@aegisgatesecurity.io

> **Note**: PGP key for encrypting vulnerability reports will be published here when available. For now, please send reports in plain text and we will provide a PGP key upon request.

**Do NOT**:
- Open a public GitHub issue for security vulnerabilities
- Discuss the vulnerability publicly before we've had time to respond
- Include sensitive data in your initial report

### What to Include

To help us triage and respond quickly, please include:

1. **Description**: Clear description of the vulnerability
2. **Impact**: What an attacker could achieve
3. **Reproduction**: Steps to reproduce the issue
4. **Environment**: OS, Go version, Rampart version
5. **Evidence**: Screenshots, logs, or proof-of-concept code (if safe to share)

### Response Timeline

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 5 business days
- **Fix Timeline**: Depends on severity (see below)

### Severity Levels

| Severity | Description | Target Fix Time |
|----------|-------------|-----------------|
| Critical | Remote code execution, auth bypass, data exfiltration | 24-72 hours |
| High | Privilege escalation, significant data exposure | 7 days |
| Medium | Limited impact, requires local access | 30 days |
| Low | Minor issues, best practice violations | 90 days |

### Disclosure Policy

We follow a coordinated disclosure process:

1. Reporter submits vulnerability privately
2. We acknowledge and assess the report
3. We develop and test a fix
4. We publish a security advisory (if appropriate)
5. We release a patched version
6. Reporter is credited (unless they prefer anonymity)

**Please allow us at least 30 days to address the issue before public disclosure.**

## Security Best Practices for Users

### Production Deployment

1. **Review default configuration**: `configs/default.json`
2. **Set appropriate log levels**: Avoid DEBUG in production
3. **Restrict proxy access**: Use firewall rules to limit who can connect
4. **Monitor detection logs**: Set up alerting for high-severity detections
5. **Keep updated**: Enable Dependabot or monitor releases
6. **Monitor config integrity**: Use file integrity monitoring (FIM) on `configs/config.json` to detect unauthorized mode changes

### CA Certificate Security

Rampart generates a local CA certificate for TLS interception:

- The CA private key never leaves your machine
- Store the CA certificate securely after installation
- Only trust the CA on machines where Rampart is installed
- Revoke and regenerate if you suspect compromise
- The CA private key file uses 0600 permissions — verify this with `ls -la`
- Use file integrity monitoring (FIM) to detect unauthorized access or modification of the CA private key

### API Endpoint Security

The `/detect` API endpoint (localhost:8080) is:

- Bound to localhost by default (not accessible from network)
- Unauthenticated (assumes local access is trusted)
- Rate-limited to prevent abuse

If you expose this endpoint beyond localhost, implement your own authentication and TLS.

## Security Advisories

Security advisories will be published as:

- GitHub Security Advisories: https://github.com/aegisgatesecurity/aegisgate-rampart/security/advisories
- GitHub Releases with security notes
- Email notifications to security mailing list (coming soon)

## Acknowledgments

We appreciate responsible disclosure and will credit researchers who report valid security issues (unless they prefer to remain anonymous).

**Security researchers who have contributed:**
- [Your name here - be the first!]

---

**Last updated**: August 17, 2026