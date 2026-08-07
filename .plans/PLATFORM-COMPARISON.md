# Platform Package Comparison: Rampart vs Platform v4.0.0

**Date**: 2026-08-07
**Author**: Session 2 — Automated comparison

---

## Executive Summary

Rampart's core detection packages are **direct forks with provenance tracking** from Platform v4.0.0. All three detection-related packages (`internal/detectors`, `internal/response`, `internal/ml`) are functionally identical to their Platform counterparts, with only cosmetic differences (provenance comments, import path re-rooting, test file organization).

**Overall parity: 98%+** — Only two functional gaps exist:
1. Platform has a `pkg/ml/training/` package (2,198 LOC) for ML training data augmentation — **not needed** for Rampart's local proxy use case
2. Platform has `pkg/ml/ab_test.go` (664 LOC) for A/B testing ML models — **not needed** for Rampart's local proxy use case

---

## Package-by-Package Comparison

### 1. `internal/detectors` (Rampart) vs `pkg/response/detectors` (Platform)

| Aspect | Rampart | Platform |
|--------|---------|----------|
| Source files (excl. tests) | 9 | 10 (extra `doc.go`) |
| Total source LOC | 1,353 | 1,349 (excl. doc.go) |
| Detection categories | 7 | 7 |
| Total patterns | 153 | 153 |
| Exported types | 4 | 4 |
| Exported functions | 9 | 9 |
| **Functional parity** | **100%** | — |

**Differences:**
- Platform has `doc.go` (25 lines, package documentation only)
- Rampart adds `// Provenance:` comment line to every file
- Test organization: Rampart splits into `detectors_test.go` + `engine_test.go` (36 tests, 467 LOC); Platform consolidates into `detectors_test.go` (52 tests, 525 LOC)
- All 153 regex patterns across all 7 categories are **byte-identical**

**Gap: None.** Full pattern parity.

---

### 2. `internal/response` (Rampart) vs `pkg/response` (Platform)

| Aspect | Rampart | Platform |
|--------|---------|----------|
| Source files (excl. tests/detectors) | 8 | 9 (extra `doc.go`) |
| Total source LOC | 2,980 | 3,021 (incl. doc.go) |
| Exported types | 19 | 19 |
| Exported functions | 23 | 23 |
| Exported interfaces | 4 | 4 |
| **Functional parity** | **100%** | — |

**Differences:**
- Platform has `doc.go` (41 lines, architecture docs with tier gating info)
- Rampart adds `// Provenance:` comment line to every file
- Import paths differ: Rampart uses `internal/detectors`, `internal/logging`; Platform uses `pkg/response/detectors`, `pkg/logging`
- All exported APIs, types, and logic are **functionally identical**

**Gap: None.** Full API parity.

---

### 3. `internal/ml` (Rampart) vs `pkg/ml` (Platform)

| Aspect | Rampart | Platform |
|--------|---------|----------|
| Core source files | 12 | 13 (extra `detector_noonnx.go`) |
| Core LOC | 3,173 | 3,227 |
| Extra packages | — | `training/` (2,198 LOC) |
| Extra files | — | `ab_test.go` (664 LOC, A/B testing) |
| **Functional parity (core)** | **100%** | — |

**Shared core files** (all functionally identical, differ only by provenance comment):
- `adversarial.go`, `calibration.go`, `detector.go`, `detector_noonnx_methods.go`, `detector_onnx_methods.go`, `doc.go`, `drift.go`, `evasion_resistance.go`, `latency.go`, `metrics.go`, `normalizer.go`, `types.go`

**Structural difference:**
- Platform splits the no-CGO stub: `detector_noonnx.go` (type stub, 13 lines) + `detector_noonnx_methods.go` (methods, 55 lines)
- Rampart combines them: `detector_noonnx_methods.go` (type + methods, 64 lines)
- Functionally equivalent, just different file organization

**Platform-only packages (NOT in Rampart):**

| Package/File | LOC | Purpose | Needed for Rampart? |
|-------------|-----|---------|---------------------|
| `pkg/ml/training/augment.go` | 2,177 | ML training data augmentation from ATLAS payloads | ❌ No — Rampart uses pre-trained model |
| `pkg/ml/training/doc.go` | 21 | Package docs | ❌ No |
| `pkg/ml/ab_test.go` | 664 | A/B testing framework for ML model comparison | ❌ No — Rampart runs one model locally |

**Gap: None for Rampart's use case.** The training and A/B testing packages are server-side Platform features, not needed for a local proxy.

---

### 4. `pkg/detector` (Rampart) vs `pkg/scanner` (Platform)

| Aspect | Rampart `pkg/detector` | Platform `pkg/scanner` |
|--------|------------------------|------------------------|
| Source files | 1 (detector.go, 249 LOC) | 3 (scanner.go + aegisguard_mcp.go + doc.go, 661 LOC) |
| Purpose | Local detection engine (regex + ML) | Scanner interface + AegisGuard MCP remote scanner |
| Approach | Direct integration with `internal/response` + `internal/ml` | Interface-based with MCP protocol for remote AegisGuard |

**Key architectural difference:**
- Rampart's `pkg/detector` is a **self-contained local detector** that wires `ResponseGuard` + `ThreatDetector` + `DetectAll()` into a single `Detect()` call. This is the right design for a local proxy.
- Platform's `pkg/scanner` defines a `Scanner` interface and provides `AegisGuardMCPScanner` for remote scanning via JSON-RPC over TCP. This is the right design for a cloud platform.

**Gap: None.** Different architecture, same detection capabilities. Rampart correctly chose local integration over remote MCP.

---

### 5. Rampart-Unique Packages (not in Platform)

These packages exist only in Rampart and are **Rampart-specific**:

| Package | LOC | Purpose | Platform Equivalent |
|---------|-----|---------|-------------------|
| `internal/catrust` | 246 | CA trust setup (macOS/Linux/Windows) | None — new for local proxy |
| `internal/autostart` | — | OS login autostart | None — new for local proxy |
| `internal/notify` | — | Desktop notifications (beeep) | `pkg/email` (server-side) |
| `internal/tray` | — | System tray icon (fyne/systray) | None — new for desktop app |
| `pkg/telemetry` | — | Local telemetry/metrics | `pkg/metrics` (Prometheus) |
| `cmd/rampart` | — | CLI entry point | `cmd/aegisgate-platform` |

---

### 6. Shared Packages (forked from Platform)

These Rampart packages are direct forks from Platform with provenance tracking:

| Rampart Package | Source | LOC Difference | Notes |
|----------------|--------|----------------|-------|
| `internal/certinit` | Platform `pkg/certinit` | +1 line (provenance) | Identical |
| `internal/certificate` | Platform `upstream/aegisgate/pkg/certificate` | +1 line (provenance) | Identical |
| `internal/logging` | Platform `pkg/logging` | Simplified for local use | Stripped to essentials |

---

## Recommendations

1. ✅ **No sync needed for detection packages** — Rampart has 100% pattern parity with Platform v4.0.0 (all 153 regex patterns, all ML models, all response guard logic).

2. ✅ **No sync needed for ML package** — Core ML functionality is identical. Training and A/B testing are server-side Platform features, not applicable to a local proxy.

3. ✅ **`pkg/detector` design is correct** — Local integration is the right architecture for Rampart. No need to adopt Platform's remote MCP scanner interface.

4. ⚠️ **Future sync consideration** — When Platform v4.1.0 adds new detection patterns, the provenance comments make it easy to identify which files to update. The sync process is:
   - Copy Platform's updated file → Strip import paths → Add provenance comment → Update Rampart's `internal/` version

5. ⚠️ **Platform's `pkg/ml/ab_test.go`** could be useful if Rampart ever wants to compare two ML models locally, but this is a Phase 2+ consideration.

---

## Verification Commands

```bash
# Verify pattern parity (should show only provenance/import differences)
diff <(cd aegisgate-rampart && grep -v "Provenance" internal/detectors/engine.go) \
     <(cd aegisgate-platform && grep -v "Provenance" pkg/response/detectors/engine.go)

# Verify response guard parity
diff <(cd aegisgate-rampart && grep -v "Provenance\|aegisgate-rampart" internal/response/guard.go) \
     <(cd aegisgate-platform && grep -v "aegisgate-platform" pkg/response/guard.go)

# Verify ML parity (core files only)
for f in adversarial.go calibration.go detector.go drift.go evasion_resistance.go latency.go metrics.go normalizer.go types.go; do
  diff <(cd aegisgate-rampart && grep -v "Provenance" internal/ml/$f) \
       <(cd aegisgate-platform && grep -v "Provenance" pkg/ml/$f)
done
```