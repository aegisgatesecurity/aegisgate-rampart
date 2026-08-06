module github.com/aegisgatesecurity/aegisgate-rampart

go 1.23

// Onnxruntime for ML inference (CGO build tag)
// Only needed when CGO_ENABLED=1 — the non-CGO build uses heuristic fallback
require github.com/yalue/onnxruntime_go v1.27.0
