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

### CA Private Key Security

The CA private key is stored on disk with **0600 file permissions** (owner read/write only). It should be protected with file integrity monitoring (FIM). **If the CA private key is compromised, an attacker could intercept all HTTPS traffic** passing through the proxy. If compromise is suspected, immediately rotate the CA key and re-install the new CA certificate on all client machines.

### Block Mode Security

In block mode, blocked request metadata (category, rule, severity) is logged, but the **original request content is not persisted**. The blocking response is only visible to the proxy operator, not the downstream AI API endpoint.

### Config Integrity

We recommend monitoring `configs/config.json` for unauthorized changes using file integrity monitoring (FIM). A change from `"mode": "block"` to `"mode": "monitor"` silently degrades security posture by allowing detected violations to pass through without blocking. Future versions may include config hash verification.

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

**Last updated**: August 7, 2026