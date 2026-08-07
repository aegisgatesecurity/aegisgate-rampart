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

## ✅ COMPLETED — Phase 2: Daemon Mode (Session 2)

- [x] System tray integration (internal/tray with fyne.io/systray)
- [x] Toast notifications for detections (internal/notify with notify-send/osascript/beeep)
- [x] Auto-start on boot (internal/autostart — launchd/systemd/registry)
- [x] PID file + daemon lifecycle (cmd/rampart/daemon.go)
- [x] Guided CA trust setup flow (--trust flag + catrust)
- [x] Phase 2 tests (cmd/rampart 20.7%→40.2%, autostart 34.8%→50.0%)

## 📋 PHASE 3: VS Code Extension (Next)

- [ ] HTTP API endpoint at localhost:8080/detect (already exists in proxy.go)
- [ ] VS Code extension scaffolding (TypeScript + Node.js API)
- [ ] Inline warnings in editor
- [ ] Detection sidebar panel
- [ ] Publish to VS Code Marketplace

## 📊 Current Coverage by Package

| Package | Coverage | Change | Notes |
|---------|----------|--------|-------|
| internal/logging | 100.0% | — | |
| pkg/telemetry | 100.0% | — | |
| internal/detectors | 96.2% | — | |
| internal/response | 90.4% | — | |
| internal/ml | 85.4% | — | |
| pkg/config | 88.2% | — | |
| internal/certinit | 82.1% | — | |
| internal/certificate | 80.5% | — | |
| pkg/detector | 82.7% | — | |
| internal/notify | 71.7% | — | Linux-only funcs |
| pkg/proxy | 58.1% | — | MITM handler needs real network |
| internal/autostart | 50.0% | +15.2% | ↑ Phase 2 tests |
| internal/catrust | 41.6% | — | Darwin/Windows-only |
| cmd/rampart | 40.2% | +19.5% | ↑ Phase 2 tests |
| internal/tray | 5.4% | — | Requires CGO/display |

**Total (all):** 76.1%
**Total (exempting cmd/rampart + internal/tray):** 83.7%

## 🔑 Key Decisions & Lessons Learned

1. **Detection engine already wired** — Phase 1 Task 1 was done in Session 1
2. **Platform v4.0.0 = 100% parity** — All 153 patterns, all APIs identical
3. **pkg/detector ≠ pkg/scanner** — Different architectures (local vs remote MCP)
4. **Integration tests gated by RAMPART_INTEGRATION=1** env var
5. **DCO sign-offs required** — All commits must have Signed-off-by
6. **Author/Committer must match** — AegisGate Security <security@aegisgatesecurity.io>

---

*Last updated: 2026-08-07*
*Sessions: 1 (Foundation), 2 (Phase 1+2 completion)*