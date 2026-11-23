<!-- SPDX-License-Identifier: Apache-2.0 -->
# ML Detection Withdrawn (2026-11-23)

**All neural ML detection in aegisgate-rampart is WITHDRAWN and hard-disabled.**

The CharCNN-BiLSTM model (sha256 `948b6500…`) expected at the configured model path was trained on a corpus whose attack-side labels failed audit (~71% flip rate). All detection-rate claims derived from it are void. The model file is removed from this repository and the loader refuses all models; `Enabled`/`ShadowMode` are forced off.

**Unaffected:** MCP proxy, scanner rules, policy checks, rate limiting — every deterministic layer.

Historical adversarial-suite reports under `internal/detectors/testing/reports/` are retained as historical record and contain void measurements.

**Reinstatement:** only after corpus re-audit, scoped rebuild, retrain, and re-baselined metrics. See the platform `docs/ML-WITHDRAWN.md` and internal report `corpus-certification-2026-11-23`.
