# Contributing to AegisGate Rampart

Thank you for your interest in contributing to Rampart! We welcome contributions from the community and believe that open-source collaboration makes security tools better for everyone.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Security Reporting](#security-reporting)

---

## Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

Examples of unacceptable behavior:

- The use of sexualized language or imagery and unwelcome sexual attention
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate

**Enforcement:** Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team at [conduct@aegisgatesecurity.io](mailto:conduct@aegisgatesecurity.io).

---

## Getting Started

### First Contributions

If you're new to open source, here's how to get started:

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a branch** for your changes
4. **Make your changes** following our standards
5. **Test thoroughly** (see Testing Requirements)
6. **Submit a pull request**

### Good First Issues

Look for issues labeled:
- [`good first issue`](https://github.com/aegisgatesecurity/aegisgate-rampart/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) - Perfect for newcomers
- [`help wanted`](https://github.com/aegisgatesecurity/aegisgate-rampart/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) - Need community help

---

## Development Setup

### Prerequisites

- **Go 1.21+** (we use latest Go features)
- **Git** for version control
- **Make** for build automation (optional but recommended)
- **Docker** for containerized testing (optional)

### Clone and Build

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/aegisgate-rampart.git
cd aegisgate-rampart

# Build
go build ./cmd/rampart

# Run tests
go test ./...
```

### Development Workflow

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make changes, then test
go test ./...

# Commit with clear messages
git commit -m "feat: add your feature description"

# Push to your fork
git push origin feature/your-feature-name
```

---

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

**🐛 Bug Fixes**
- Fix issues in [GitHub Issues](https://github.com/aegisgatesecurity/aegisgate-rampart/issues)
- Include regression tests

**✨ New Features**
- Propose feature via GitHub Issue first
- Explain use case and implementation approach
- Include comprehensive tests

**📚 Documentation**
- Improve README, examples, or comments
- Fix typos or clarify confusing sections
- Add tutorials or guides

**🧪 Tests**
- Increase test coverage
- Add edge case tests
- Improve test reliability

**🔒 Security**
- Report vulnerabilities responsibly (see [Security Reporting](#security-reporting))
- Help fix security issues
- Improve security documentation

**🚀 Performance**
- Optimize slow code paths
- Reduce memory usage
- Improve startup time

### Reporting Bugs

**Before reporting:**
1. Search existing issues to avoid duplicates
2. Check if issue persists in latest version
3. Gather relevant information

**Bug report template:**
```markdown
**Description:** Clear description of the bug

**To Reproduce:**
1. Step 1
2. Step 2
3. Step 3

**Expected:** What should happen
**Actual:** What actually happens

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Go version: [e.g., 1.21.0]
- Rampart version: [e.g., 0.5.0]

**Logs:** Relevant error messages or logs
```

### Requesting Features

**Before requesting:**
1. Search existing issues for similar requests
2. Consider if feature aligns with project goals
3. Think about implementation approach

**Feature request template:**
```markdown
**Problem:** What problem does this solve?

**Proposal:** Describe the feature

**Use Case:** Who needs this and why?

**Alternatives:** What alternatives have you considered?

**Implementation:** How might this be implemented?
```

---

## Coding Standards

### Go Style

We follow standard Go conventions:

- **Formatting:** `gofmt` or `goimports` (enforced in CI)
- **Naming:** Clear, descriptive names (no abbreviations unless common)
- **Comments:** Document exported functions, types, and packages
- **Error Handling:** Check errors, don't ignore them
- **Imports:** Group standard library, third-party, and local imports

### Code Organization

```
aegisgate-rampart/
├── cmd/           # CLI applications
├── pkg/           # Public libraries
├── internal/      # Private implementation
├── configs/       # Default configurations
├── packaging/     # Distribution packages
└── .plans/        # Development plans (internal)
```

### Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new detection category
fix: resolve race condition in proxy
docs: update README examples
test: add edge case tests for XSS detector
refactor: simplify certificate management
perf: optimize regex compilation
chore: update dependencies
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code restructuring (no behavior change)
- `perf`: Performance improvements
- `chore`: Maintenance tasks

---

## Testing Requirements

### Mandatory Testing

**All PRs must include:**

1. **Unit Tests** for new functionality
2. **Integration Tests** for feature workflows
3. **No Regression** - existing tests must pass

### Test Coverage

**Expectations:**
- New code: **80%+ coverage** (minimum)
- Critical paths: **100% coverage** (security, privacy, core logic)
- CLI entry points: Lower coverage acceptable (wiring only)

**Run tests:**
```bash
# All tests
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test ./pkg/proxy/...

# Verbose output
go test -v ./...
```

### Test Quality

**Good tests:**
- ✅ Test behavior, not implementation
- ✅ Include edge cases
- ✅ Are deterministic (no flaky tests)
- ✅ Clean up after themselves (use `t.TempDir()`)
- ✅ Have descriptive names

**Example:**
```go
func TestProxy_BlocksHighSeverityDetections(t *testing.T) {
    // Arrange
    cfg := &config.Config{Mode: config.ModeBlock}
    proxy := New(cfg)
    
    // Act
    result := proxy.Detect(testSSNPayload)
    
    // Assert
    if !result.Blocked {
        t.Error("Expected high-severity SSN detection to be blocked")
    }
}
```

---

## Pull Request Process

### Before Submitting

**Checklist:**
- [ ] Code follows style guidelines
- [ ] Tests added/updated
- [ ] All tests pass (`go test ./...`)
- [ ] Documentation updated (if needed)
- [ ] Commit messages are clear
- [ ] Branch is up-to-date with main

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] All existing tests pass
- [ ] Manual testing performed

## Checklist
- [ ] Code follows project standards
- [ ] Self-review completed
- [ ] Comments added where needed
- [ ] Documentation updated
```

### Review Process

1. **Automated Checks:** CI runs tests, linting, security scans
2. **Maintainer Review:** At least one maintainer must approve
3. **Discussion:** Address feedback and iterate
4. **Merge:** Squash and merge when approved

**Review Time:** We aim to review PRs within 48 hours

---

## Security Reporting

### Responsible Disclosure

**If you find a security vulnerability:**

1. **DO NOT** open a public issue
2. **Email:** [security@aegisgatesecurity.io](mailto:security@aegisgatesecurity.io)
3. **Include:** Description, impact, reproduction steps
4. **Wait:** Allow 30 days for us to respond and fix

### Security Contributions

**Helping with security:**
- Review security-related PRs
- Help fix reported vulnerabilities
- Improve security documentation
- Suggest security enhancements

See [SECURITY.md](SECURITY.md) for complete policy.

---

## Community

### Communication

- **GitHub Issues:** Bug reports, feature requests
- **GitHub Discussions:** Questions, ideas, community support
- **Email:** [info@aegisgatesecurity.io](mailto:info@aegisgatesecurity.io) for general inquiries

### Recognition

We recognize contributors via:
- GitHub contributor graph
- Release notes acknowledgments
- Special thanks in documentation

**Top contributors:**
- [Your name here - be the first!]

---

## Legal

### License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).

### Contributor License Agreement (CLA)

**Individual Contributors:**
By submitting a PR, you grant AegisGate Security a perpetual, worldwide, non-exclusive, royalty-free license to use your contribution.

**Corporate Contributors:**
If you're contributing on behalf of your employer, ensure you have authorization to contribute to this project.

---

## Questions?

**Need help?**
- Check existing [Issues](https://github.com/aegisgatesecurity/aegisgate-rampart/issues)
- Read [README.md](README.md) and [PRIVACY.md](PRIVACY.md)
- Ask in [GitHub Discussions](https://github.com/aegisgatesecurity/aegisgate-rampart/discussions)
- Email: [info@aegisgatesecurity.io](mailto:info@aegisgatesecurity.io)

**Thank you for contributing to AegisGate Rampart!** 🎉

Together, we're building better AI security for everyone.

---

**Last updated:** August 8, 2026  
**Version:** 1.0 (v0.5.1 release)
