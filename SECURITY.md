# Security Policy

## Supported Versions

AegisGate Rampart follows semantic versioning. Security updates are provided for the latest minor version and the previous major version during transition periods.

| Version | Supported          |
| ------- | ------------------ |
| 4.x.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Security Architecture

Rampart is designed with security as a first principle:

- **Air-gap ready**: Zero phone-home when `PlatformURL` is empty
- **Local-first**: All detection logic runs locally on your machine
- **No data retention**: Request/response data is not stored unless explicitly configured
- **Transparent proxy**: MITM certificates are generated locally and never transmitted
- **Open source**: All code is auditable under Apache 2.0 license

## Reporting a Vulnerability

We take the security of Rampart seriously. If you believe you've found a security vulnerability, please report it responsibly.

### How to Report

**Email**: security@aegisgatesecurity.io

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

### CA Certificate Security

Rampart generates a local CA certificate for TLS interception:

- The CA private key never leaves your machine
- Store the CA certificate securely after installation
- Only trust the CA on machines where Rampart is installed
- Revoke and regenerate if you suspect compromise

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

**Last updated**: August 6, 2026
