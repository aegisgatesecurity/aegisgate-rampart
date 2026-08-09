# AegisGate Rampart Packaging Guide

This directory contains packaging infrastructure for distributing AegisGate Rampart across different platforms.

## Quick Start

### Build All Packages
```bash
make -f Makefile.packaging all
```

### Build Specific Package
```bash
# Debian/Ubuntu
make -f Makefile.packaging package-deb

# RHEL/Fedora/Rocky
make -f Makefile.packaging package-rpm

# Homebrew (macOS/Linux)
make -f Makefile.packaging package-brew
```

---

## Debian/Ubuntu Package

### Build Requirements
- `dpkg-deb`
- Go 1.24+

### Build
```bash
make -f Makefile.packaging package-deb
```

### Output
`packaging/debian/aegisgate-rampart_0.5.0_amd64.deb`

### Install
```bash
sudo dpkg -i aegisgate-rampart_0.5.0_amd64.deb
sudo apt-get install -f  # Fix dependencies if needed
```

### Uninstall
```bash
sudo apt-get remove aegisgate-rampart
```

### Post-Install
The package automatically:
1. Creates `/etc/aegisgate-rampart` config directory
2. Copies default config
3. Attempts to install CA certificate (requires user confirmation)

---

## RPM Package (RHEL/Fedora/Rocky)

### Build Requirements
- `rpmbuild`
- Go 1.24+
- gcc (for CGO on macOS)

### Build
```bash
make -f Makefile.packaging package-rpm
```

### Output
`packaging/redhat/RPMS/x86_64/aegisgate-rampart-0.5.0-1.x86_64.rpm`

### Install
```bash
sudo rpm -ivh aegisgate-rampart-0.5.0-1.x86_64.rpm
# or
sudo dnf install ./aegisgate-rampart-0.5.0-1.x86_64.rpm
```

### Uninstall
```bash
sudo rpm -e aegisgate-rampart
```

---

## Homebrew Tap (macOS/Linux)

### Setup Tap Repository
1. Create repository: `aegisgatesecurity/homebrew-tap`
2. Copy `packaging/homebrew/aegisgate-rampart.rb` to root
3. Update SHA256 hash in formula
4. Commit and push

### User Installation
```bash
brew tap aegisgatesecurity/tap
brew install aegisgate-rampart
```

### Update Formula
When releasing new version:
1. Update `url` and `sha256` in formula
2. Commit to tap repository
3. Users run `brew update && brew upgrade aegisgate-rampart`

---

## Testing Packages

### Test in Clean Docker Containers
```bash
# Test Debian package
make -f Makefile.packaging test-deb

# Test RPM package
make -f Makefile.packaging test-rpm
```

### Manual Testing
1. Create clean VM (VirtualBox, etc.)
2. Install package
3. Verify: `rampart version`, `rampart --help`
4. Test CA trust: `rampart --trust`
5. Test proxy: `rampart --port 9090`

---

## GitHub Releases Integration

### Upload to Release
```bash
make -f Makefile.packaging release
```

This uploads `.deb` and `.rpm` packages to GitHub Releases.

### Release Checklist
- [ ] Build binaries for Linux/macOS/Windows
- [ ] Build .deb package
- [ ] Build .rpm package
- [ ] Update Homebrew formula
- [ ] Upload all to GitHub Releases
- [ ] Update release notes with install instructions

---

## Package Contents

### Debian/RPM
- `/usr/bin/rampart` - Main binary
- `/etc/aegisgate-rampart/` - Config directory
- `/usr/share/doc/aegisgate-rampart/` - Documentation

### Homebrew
- `/usr/local/bin/rampart` (Intel) or `/opt/homebrew/bin/rampart` (Apple Silicon)
- Config in `~/.config/aegisgate-rampart/`

---

## Version Numbering

Follow semantic versioning: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

Update `VERSION` file before building packages.

---

## Signing Packages (Optional)

### Debian
```bash
dpkg-sig --sign builder aegisgate-rampart_0.5.0_amd64.deb
```

### RPM
```bash
rpm --addsign aegisgate-rampart-0.5.0-1.x86_64.rpm
```

### Homebrew
Bottles are signed automatically by Homebrew.

---

## Troubleshooting

### Debian: "dpkg-deb: error"
Ensure all directories exist and permissions are correct.

### RPM: "rpmbuild: command not found"
Install RPM build tools:
- RHEL/Fedora: `sudo dnf install rpm-build`
- Ubuntu: `sudo apt-get install rpm`

### Homebrew: "SHA256 mismatch"
Download the tarball and calculate correct SHA256:
```bash
curl -L https://github.com/aegisgatesecurity/aegisgate-rampart/archive/v0.5.0.tar.gz | sha256sum
```

---

## Next Steps

1. **Automated Builds**: Set up GitHub Actions to build packages on release
2. **Repository Hosting**: Create apt/yum repositories for easy updates
3. **Code Signing**: Sign packages for verified publishers
4. **Auto-Updates**: Integrate with system update mechanisms

---

*For more information, see README.md in the project root.*
