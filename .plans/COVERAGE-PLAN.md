# Coverage Improvement Plan — Target: 95%+ Project-Wide

## Current Coverage (After Round 1)

| Package | Baseline | Current | Change | Target | Blocker |
|---------|----------|---------|--------|--------|----------|
| pkg/proxy | 58.1% | 61.9% | +3.8% | 95% | Start/tunnel/interceptHTTPS need network I/O |
| cmd/rampart | 40.2% | 40.2% | — | 90% | main/runDaemon/watchDetections need integration |
| internal/catrust | 41.6% | 41.6% | — | 85% | darwin/windows code can't run on Linux CI |
| internal/autostart | 50.0% | 50.0% | — | 85% | darwin/windows code can't run on Linux CI |
| internal/tray | 5.4% | 5.4% | — | 70% | CGO/display — hard exemption needed |
| internal/notify | 71.7% | 79.2% | +7.5% | 95% | darwin/windows platform code |
| internal/certificate | 80.5% | 80.5% | — | 95% | needs deeper testing |
| internal/certinit | 82.1% | 82.1% | — | 95% | needs deeper testing |
| internal/ml | 85.4% | 85.4% | — | 95% | model loading fails |
| internal/response | 90.4% | 90.4% | — | 98% | close to target |
| pkg/detector | 82.7% | 82.7% | — | 95% | needs deeper testing |
| pkg/config | 88.2% | 88.2% | — | 95% | close to target |
| internal/detectors | 96.2% | 96.2% | — | 98% | nearly done |
| internal/logging | 100% | 100% | — | 100% | done |
| pkg/telemetry | 100% | 100% | — | 100% | done |

## Exemptions Required

1. **internal/tray** (5.4% → exempt): `systray.Run`, `onReady`, `handleMenu`, `SetRunning`, `UpdateDetections`,
   `IncrementDetections`, `SetIconFromBytes`, `Exit` all require CGO + display server. Cannot be unit tested.
   Recommendation: Add `//go:build !cgo` build tag exemption in CI config.

2. **pkg/proxy** (tunnel 31.6%, interceptHTTPS 14%, Start 0%): These functions require real TCP/TLS connections.
   Integration tests exist in `proxy_mitm_test.go` (gated behind `RAMPART_INTEGRATION=1`).
   Recommendation: Run integration tests in CI with `RAMPART_INTEGRATION=1`.

3. **cmd/rampart** (main 0%, runDaemon 0%, Daemon.Run 0%): These functions call `os.Exit` or start
   long-running goroutines. Integration tests needed.
   Recommendation: Add subprocess-based tests.

4. **Platform-specific code**: `internal/catrust` (darwin/windows 0%), `internal/autostart` (darwin 0%, windows 0%),
   `internal/notify` (darwin 0%, windows 0%). Build-constraint test files added for cross-platform CI.
   Recommendation: Add macOS and Windows CI runners.

## Strategy by Package

### pkg/proxy (58.1% → 95%)
**Uncovered:** `Start` (0%), `tunnel` (31.6%), `interceptHTTPS` (14%), `handleCONNECT` (58.3%), `handleHTTP` (72.4%), `scanAndAlert` (68.8%)

**Approach:**
- Start/Shutdown lifecycle tests (port 0, context cancel)
- HTTP handler tests via httptest.Server for handleHTTP paths
- scanAndAlert with all result variants (blocked, ML score, PII categories)
- handleCONNECT routing tests (target vs non-target domain)
- Tunnel tests with real TCP echo server
- Integration tests (gated) for full MITM flow

### cmd/rampart (40.2% → 90%)
**Uncovered:** `main()` (0%), `runDaemon()` (0%), `Daemon.Run()` (0%), `watchDetections` (0%), `runForeground` (75%)

**Approach:**
- Extract testable logic from main() into a run() function
- Test handleTrust, handleAutoStart, handleStatus more thoroughly
- Test runForeground with full lifecycle (start, signal, shutdown)
- Daemon.Run and watchDetections need integration tests (gated)
- Test main() via subprocess test pattern

### internal/catrust (41.6% → 85%)
**Uncovered:** `checkTrustDarwin` (0%), `setupTrustDarwin` (0%), `checkTrustWindows` (0%), `setupTrustWindows` (0%), `checkTrustLinux` (71.4%), `setupTrustLinux` (50%)

**Approach:**
- Platform-specific code can't run on other OSes — need build-tag tests
- Test `GetInstructions` for all platforms via string assertions
- Test `CheckTrust` and `SetupTrust` routing for each platform
- Linux-specific: test `checkTrustLinux` with temp cert files
- Darwin/Windows: test with build-tag stub tests or exec.Command mocks

### internal/autostart (50.0% → 85%)
**Uncovered:** `enableDarwin` (0%), `disableDarwin` (0%), `isEnabledDarwin` (0%), `disableWindows` (0%), `isEnabledWindows` (0%), `Enable/Disable/IsEnabled` routing (40%)

**Approach:**
- Darwin functions: write plist content, verify path, test enable/disable on macOS
- Windows functions: already tested .reg file generation, test disable/isEnabled
- Test routing functions with OS mocks or direct calls on appropriate platforms
- Cross-platform: test all paths via exec.Command interception

### internal/tray (5.4% → 70%)
**Uncovered:** Almost everything — `Run`, `onReady`, `onExit`, `handleMenu`, `SetRunning`, `UpdateDetections`, `IncrementDetections`, `SetIconFromBytes`, `Exit`

**Approach:**
- Requires CGO/display for `fyne.io/systray` — can't test in headless CI
- Test what we can without CGO: struct defaults, Config, New
- Add `//go:build !cgo` test stubs for non-CGO builds
- SetRunning, UpdateDetections, IncrementDetections need nil menu items (panic risk)
- **Exemption**: systray.Run() and onReady/onExit/onMenu need real display server
- Target 70% with exemption for CGO-dependent code

### internal/notify (71.7% → 95%)
**Uncovered:** `Send` (62.5%), `ensureDefaultIcon` (44.4%), `notifyDarwin` (0%), `notifyWindows` (0%)

**Approach:**
- Test Send on Linux (with notify-send mock or skip if not installed)
- Test ensureDefaultIcon: icon dir creation, existing icon path
- Test resolveIcon: all branches (per-notification, notifier default, fallback)
- Platform-specific functions: build-tag tests for darwin/windows

## Execution Order
1. ✅ Fix CI lint failures (errcheck) — DONE
2. 🔜 internal/notify — easiest wins, 71.7% → 95%
3. 🔜 internal/catrust — 41.6% → 85%
4. 🔜 internal/autostart — 50.0% → 85%
5. 🔜 cmd/rampart — 40.2% → 90%
6. 🔜 pkg/proxy — 58.1% → 95%
7. 🔜 internal/tray — 5.4% → 70% (with exemptions)
8. 🔜 Remaining packages polish