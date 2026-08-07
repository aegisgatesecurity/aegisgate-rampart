# AegisGate Rampart — Development TODO

## ✅ COMPLETED — Phase 1: CLI Proxy Mode (Sessions 1-2)

- [x] Wire detection engine (pkg/detector → internal/response + ml + detectors)
- [x] TLS interception for target domains (handleCONNECT/interceptHTTPS/tunnel)
- [x] CA certificate generation on first run (certinit.EnsureCerts + --trust)
- [x] Detection result output to terminal (color-coded severity)
- [x] Config file loading (DefaultConfig + --config flag)
- [x] Build and test (make build, 15 packages pass -race)
- [x] Integration tests (proxy_mitm_test.go, catrust_integration_test.go)
- [x] Platform v4.0.0 comparison (100% parity, no sync needed)
- [x] DCO sign-offs (all 47 commits properly signed)

## ✅ COMPLETED — Phase 2: Daemon Mode (Session 2-3)

- [x] System tray integration (internal/tray with fyne.io/systray)
- [x] Toast notifications for detections (internal/notify with notify-send/osascript/beeep)
- [x] Auto-start on boot (internal/autostart — launchd/systemd/registry)
- [x] PID file + daemon lifecycle (cmd/rampart/daemon.go)
- [x] Guided CA trust setup flow (--trust flag + catrust)
- [x] Phase 2 tests (cmd/rampart 40.2%, autostart 50.0%)
- [x] E2E integration tests (TestE2E_FullTLSRoundTrip + TestE2E_DetectionPipeline)
- [x] TotalDetections bug fix, DEECTION typo fix, notification icon RGB→RGBA fix

## 📋 PHASE 3A: Windows Port (Priority)

- [ ] **CRITICAL**: Add `//go:build linux` to `notify_platform_test.go` (build breaker on Windows)
- [ ] Create `internal/platform/paths.go` for platform-aware config directories (`os.UserConfigDir()`)
- [ ] Replace all `filepath.Join(home, ".config", "aegisgate-rampart")` with `platform.ConfigDir()`
- [ ] Fix signal handling for Windows (create `signal_unix.go` + `signal_windows.go` with build tags)
- [ ] Fix PID file process check for Windows in `daemon.go`
- [ ] Add Windows ONNX runtime search paths (`.dll` instead of `.so`)
- [ ] Direct Registry write for Windows auto-start (using `golang.org/x/sys/windows/registry`)
- [ ] Add Windows CI runner to `.github/workflows/ci.yml`
- [ ] Verify cross-compilation: `GOOS=windows go vet ./...` and `GOOS=darwin go vet ./...`

## 📋 PHASE 3B: VS Code Extension

- [ ] HTTP API endpoint at localhost:8080/detect (already exists in proxy.go)
- [ ] VS Code extension scaffolding (TypeScript + Node.js API)
- [ ] Inline warnings in editor
- [ ] Detection sidebar panel
- [ ] Publish to VS Code Marketplace

## 📊 Current Coverage by Package

| Package | Coverage | Notes |
|---------|----------|-------|
| pkg/telemetry | 100.0% | ✅ |
| internal/logging | 100.0% | ✅ |
| internal/detectors | 96.2% | ✅ |
| internal/certinit | 96.6% | ✅ |
| pkg/config | 94.1% | ✅ |
| internal/response | 93.8% | ✅ |
| pkg/detector | 92.5% | ✅ |
| internal/ml | 86.6% | ✅ |
| internal/certificate | 85.1% | ✅ |
| internal/notify | 77.4% | ⚠️ Linux-only, darwin/win gated |
| pkg/proxy | 61.9% | ⚠️ MITM paths need live network |
| internal/autostart | 50.0% | ⚠️ platform-specific |
| internal/catrust | 41.6% | ⚠️ darwin/win code needs root |
| cmd/rampart | 40.2% | ⚠️ main entrypoint, exempt |
| internal/tray | 5.4% | ⚠️ CGO/gui, exempt |

---

*Last updated: 2026-08-07*
*Sessions: 1 (Foundation), 2 (Phase 1+2 completion), 3 (E2E tests, coverage, Windows assessment)*