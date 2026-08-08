# Changelog

All notable changes to AegisGate Rampart are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-08-07

### Added — Phase 7: Security Hardening + Operational Endpoints

- **P0: Audit log redaction**: Secret values fully redacted to `[REDACTED]`, PII values partially
  masked (e.g., `26***34`), XSS/compliance text passed through unchanged
  - `RedactText()` function in `internal/auditlog` package
  - `Redacted` field on audit log `Entry` struct for compliance verification
  - Audit log comment updated to document redaction policy
- **P0: CA key encryption at rest**: AES-256-GCM encryption for CA private keys
  - `EncryptKey()` / `DecryptKey()` in `internal/certificate` using HKDF-SHA256 key derivation
  - `SaveEncrypted()` / `LoadEncrypted()` for transparent encrypted file I/O
  - `--ca-key-passphrase` CLI flag for passphrase-based encryption
  - Startup warning when CA key is stored unencrypted (no passphrase provided)
  - Encrypted PEM type: `ENCRYPTED PRIVATE KEY`
- **P0: SECURITY.md updated**: Fixed version (0.x.x not 4.x.x), added audit log data handling,
  CA key security, block mode security, config integrity, PGP reporting note
- **P0: THREAT-MODEL.md created**: Complete threat model document with trust boundaries, assets
  protected, threats addressed, out-of-scope threats, threats TO Rampart, security assumptions
- **P4: pprof memory monitoring**: `--pprof` flag enables Go pprof debug server
  - Endpoints: `/debug/pprof/`, `/debug/pprof/heap`, `/debug/pprof/goroutine`, etc.
  - Graceful shutdown of pprof server with 5s timeout
- **P5: `/health` and `/ready` endpoints**: Production deployment readiness
  - `GET /health` → `{"status":"ok"}` (liveness probe)
  - `GET /ready` → `{"status":"ready","detector":true}` (readiness probe)
- **P5: Request body size limit on `/detect`**: 10MB max to prevent compute abuse

### Changed

- Go version upgraded from 1.23 to 1.25.0 (for `crypto/hkdf` stdlib support)
- `golang.org/x/crypto` added as dependency (v0.54.0)
- `golang.org/x/sys` upgraded from v0.30.0 to v0.47.0
- `PprofAddr` and `CAKeyPassphrase` fields added to `Config` struct
- `Proxy` struct includes `pprofServer` field for debug server lifecycle

### Testing

- 7 new CA key encryption tests (round-trip, wrong passphrase, empty passphrase, SaveEncrypted, LoadEncrypted, file permissions, invalid data)
- 3 new endpoint tests (health, readiness, max body size)
- All 19 packages pass with `-race` flag
- Coverage: internal/auditlog 86.5% → higher (with RedactText tests)
- Coverage: internal/certificate 85.1% → higher (with Encrypt/Decrypt tests)

### Added — Phase 6: Block Mode + k6 Load Testing

- **Block Mode**: Active threat blocking (CLI flag `--block` or config `"mode": "block"`)
  - `shouldBlock()`: Severity-threshold and category-filter based blocking decisions
  - `blockResponse()`: Structured JSON 403 response with detection details
  - `formatBlockHTTPResponse()`: Raw HTTP response for MITM proxy path
  - Blocks both outbound requests (user → AI) and inbound responses (AI → user)
  - Configurable: threshold (low/medium/high/critical), categories, status code, message
  - `BlockConfig` struct with full JSON configuration support
  - `--block` CLI shorthand for `--mode=block`
  - Stats API includes `"mode"` field ("monitor" or "block")
  - Terminal output shows `[BLOCKED]` tag in block mode
- **k6 Load Testing Suite** (7 test scripts, 1,817 LOC):
  - `stress-test.js`: Baseline graduated load (5→100 VUs)
  - `break-test.js`: Find the ceiling — 1x→20x progressive load (1,000 VUs peak)
  - `crush-test.js`: Sequential crush with recovery (2,000 VUs peak)
  - `malformed-input-test.js`: Invalid JSON, oversized, binary, unicode, HTTP abuse
  - `rate-limit-test.js`: Rate limiter enforcement verification
  - `connection-flood-test.js`: Rapid open/close, connection storms (500 VUs)
  - `endurance-test.js`: 5-minute sustained load (memory leak detection)
  - `run-all.sh` orchestrator, `README.md` with usage instructions
  - Verified: 1.19M requests, 0% crash rate across all tests
- **Configurable rate limiting**: `--rate-limit` flag and `RateLimitRPS` config field
- **CA trust bug fix**: `checkTrustDarwin` and `checkTrustWindows` now check file existence
  before querying system keychain (fixes macOS CI failure)
- **Audit log coverage**: Raised from 61.5% to 86.5% (7 new tests for rotate, copyFile, etc.)

### Changed

- `ProxyStats` now includes `mode` field (monitor/block)
- `scanAndAlert()` now returns `*detector.Summary` for block decisions
- Recovery verdicts in k6 tests use crash_rate (not success_rate) to avoid false negatives
- Default rate limit changed from 30 RPS to configurable (default still 30)

### Testing

- 10 new block mode unit tests (monitor mode, block mode, threshold, categories, API)
- k6 load test suite: 1.19M requests, 0% crash rate, all 7 tests pass
- All 19 packages pass with `-race` flag

## [0.3.0] - 2026-08-07

### Added — Phase 5: IDE Coverage Expansion

- JetBrains IDE plugin (`aegisgate-rampart-jetbrains/`): IntelliJ, PyCharm, WebStorm, etc.
  - RampartClient: HTTP client to localhost /detect + /stats (zero-dep JSON parser)
  - RampartAnnotator + RampartExternalAnnotator: inline highlights with severity icons
  - RampartAutoScan: debounced document-change listener (300ms)
  - RampartStatusBar: live connection status (30s refresh)
  - RampartSettings: persistent IDE settings (URL, auto-scan, min severity)
  - RampartActions: Scan Current File, Check Connection, Open Settings
  - 18 unit tests, 1.6MB plugin ZIP
  - Requires IntelliJ Platform 2023.2+ (JDK 17)
  - Zero external runtime dependencies beyond IntelliJ SDK
- LSP server (`cmd/rampart-lsp/` + `internal/lsp/`): any-editor coverage
  - JSON-RPC 2.0 over stdio — works with Neovim, Emacs, Helix, Sublime, etc.
  - Debounced scanning (300ms default, configurable)
  - Severity threshold filtering (critical/high/medium/low)
  - Category icons in diagnostic messages (🔐💳⚔️🔑🧠📋)
  - Configurable: --rampart-url, --debounce-ms, --min-severity
  - Zero external dependencies (Go stdlib only)
  - 91.5% test coverage, all passing with -race

### Added — CI and Repositories

- VS Code extension pushed to `github.com/aegisgatesecurity/aegisgate-rampart-ext`
- JetBrains plugin CI workflow (Gradle build + test + artifact upload)
- LSP server coverage raised from 67.4% to 91.5% (22 new tests)
- Fixed IntelliJ Platform API compatibility issues (6 fixes)
- Fixed JSON parser false key matches in JetBrains plugin
- Fixed errcheck lint failures in LSP test files

## [0.2.1] - 2026-08-07

### Added — P0: Audit Log & Platform Forwarding

- Local audit log (`internal/auditlog`): JSONL persistence of detection events
  - Writes to `~/.local/share/aegisgate-rampart/audit.log` (Linux), `~/Library/Application Support/aegisgate-rampart/audit.log` (macOS), `%AppData%\AegisGate Rampart\audit.log` (Windows)
  - Size-based rotation (10 MB default) with timestamped backups
  - Fsync after every write for durability
  - **No prompt text, no PII values, no credentials** — only metadata (category, rule, severity, host, path)
- Platform forwarding (`internal/platformforward`): push detection metadata to AegisGate Platform
  - Opt-in via `platform_url` config field (empty = disabled, air-gap compatible)
  - Async HTTP POST with 5s timeout
  - **Same privacy guarantee**: only metadata forwarded, never prompt text or PII values
  - Non-blocking on error (connection refused, server error → log and continue)
- Proxy integration: every detection now writes to audit log AND forwards to Platform (if configured)
- Audit log closed on graceful shutdown

## [0.2.0] - 2026-08-07

### Added — Phase 4: Production Hardening

- Graceful shutdown with connection draining (15s timeout via `http.Server.Shutdown`)
- Rate limiting on `/detect` and `/stats` API endpoints (30 req/s burst, 429 on exceed)
- Configuration hot-reload on SIGHUP (Unix) — reloads `config.json` without restart
- `ReloadConfig()` method on Proxy for live target updates
- `ConfigPath()` helper in config package for reload file watching
- `reloadSignal()` platform abstraction (SIGHUP on Unix, nil on Windows)
- Security audit: verified no prompt text in `log.Printf` output — only category/rule names
- Security audit: `ProxyStats` contains only counts, no sensitive data
- Security tests: `TestSecurityAudit_NoPromptTextInLogs`, `TestSecurityAudit_RateLimitPreventsAbuse`, `TestSecurityAudit_NoDataRetention`
- Rate limit tests: method not allowed, 429 response, concurrent burst behavior
- Graceful shutdown test: context cancellation + drain verification
- Config reload test: target domain addition/removal verification
- Signal tests for SIGHUP (Unix) and nil reload (Windows)

## [0.1.0] - 2026-08-07

### Added
- HTTPS MITM proxy for 27 AI API endpoints
- CA certificate generation and trust flow (`--trust`, `--status`)
- Detection engine: 153 regex patterns + Char CNN-BiLSTM ML heuristic
- PII scanner (SSN, credit cards, emails, phones, international PII)
- Secret detector (API keys, bearer tokens, JWTs)
- Hallucination detector, toxicity filter, token limiter
- Response guard (scan AI responses before delivery)
- Desktop notifications (Linux notify-send, macOS osascript, Windows beeep)
- System tray integration (fyne.io/systray)
- Auto-start on boot (systemd, launchd, Windows Registry)
- Daemon mode with PID file lifecycle (`--daemon`)
- HTTP API endpoints (`/detect`, `/stats`)
- E2E integration tests (gated by `RAMPART_INTEGRATION=1`)
- Cross-platform support: Linux, macOS, Windows
- Platform-aware config directories (XDG on Linux, AppData on Windows, Library on macOS)
- Platform-aware signal handling (SIGINT+SIGTERM on Unix, SIGINT on Windows)
- Windows Registry auto-start (direct HKCU write with .reg fallback)
- macOS ONNX runtime search paths (Homebrew Intel + Apple Silicon)
- Windows ONNX runtime search paths (.dll)
- CI: Linux (ubuntu-latest), macOS (macos-latest + CGO), cross-compile (Windows, ARM64)
- Release workflow: Linux/Windows (CGO_ENABLED=0), macOS (CGO_ENABLED=1 on macos-latest)
- DCO enforcement in CI
- 80% coverage floor in CI (exempting cmd/rampart, internal/tray)
- golangci-lint + go vet + gofmt checks in CI

### Fixed
- TotalDetections undercount bug (DetectAll results not counted)
- Notification icon not rendering (RGB→RGBA with transparent background)
- DEECTION→DETECTION typo in terminal output
- Build-breaking missing `//go:build linux` tag on notify_platform_test.go
- Hardcoded `~/.config/aegisgate-rampart` paths replaced with `platform.ConfigDir()`
- ineffectual assignment in E2E test
- Windows/darwin test name collisions