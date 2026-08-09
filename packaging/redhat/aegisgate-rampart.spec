Name:           aegisgate-rampart
Version:        0.6.0
Release:        1%{?dist}
Summary:        Local AI security proxy for intercepting and detecting threats
License:        Apache-2.0
URL:            https://github.com/aegisgatesecurity/aegisgate-rampart
Source0:        https://github.com/aegisgatesecurity/aegisgate-rampart/archive/v%{version}.tar.gz

Requires:       ca-certificates

%description
AegisGate Rampart is a local HTTPS MITM proxy that intercepts traffic to AI API
endpoints, runs real-time detection for PII, secrets, XSS, and compliance
violations, and can actively block threats before they reach the AI service.

Features:
- 153 regex patterns + Char CNN-BiLSTM neural network
- Monitor mode (log only) or Block mode (active blocking)
- System tray notifications (daemon mode)
- Auto-start on boot
- IDE integration (VS Code, JetBrains)
- Compliance mapping (SOC2, GDPR, HIPAA, PCI-DSS)
- Privacy-first (no telemetry by default)

%prep
%setup -q

%build
# Binary is pre-built in the source tarball
echo "Using pre-built binary"

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/aegisgate-rampart
mkdir -p %{buildroot}/usr/share/doc/aegisgate-rampart

install -m 755 rampart %{buildroot}/usr/bin/
install -m 644 README.md %{buildroot}/usr/share/doc/aegisgate-rampart/
install -m 644 LICENSE %{buildroot}/usr/share/doc/aegisgate-rampart/

%post
echo "Setting up AegisGate Rampart..."
if command -v rampart >/dev/null 2>&1; then
    rampart --trust 2>/dev/null || true
fi
echo "✓ AegisGate Rampart installed successfully"
echo "  Run 'rampart --trust' to install the CA certificate"

%files
/usr/bin/rampart
/etc/aegisgate-rampart
/usr/share/doc/aegisgate-rampart/README.md
/usr/share/doc/aegisgate-rampart/LICENSE

%changelog
* Sat Aug 08 2026 AegisGate Security <security@aegisgate.dev> - 0.6.0-1
- v0.6.0 release
