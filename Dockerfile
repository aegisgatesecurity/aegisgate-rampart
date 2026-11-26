# SPDX-License-Identifier: Apache-2.0
# AegisGate Rampart — Multi-stage Production Build
# =========================================================================
# Build:  docker build -t aegisgate-rampart:latest .
# Run:    docker run -p 8080:8080 aegisgate-rampart:latest
#
# ML detection is WITHDRAWN (2026-11-23): the neural model is withheld from
# this image; LoadModel is hard-disabled and the container runs deterministic
# detection only. See docs/ML-WITHDRAWN.md.
# ORT EXCISED 2026-11-26 (user-approved): ONNX Runtime removed from the build
# entirely — CGO_ENABLED=0 pure-Go build, no ORT download (upstream release
# URLs are dead, gotcha #280). Future ML (if any) must be Go-native per the
# Phase 4b constraint (no CGO, no vendored native libs).
#
# Uses Debian bookworm-slim base (not Alpine) for production-stage tooling
# compatibility. The ~67MB size increase over Alpine is acceptable
# for a production security tool.
#
# Hardening:
#   - Production stage runs as non-root via USER appuser.
#   - Only ca-certificates added (minimal attack surface).
# =========================================================================

# Builder stage: Go on Debian bookworm (pure Go, no CGO).
FROM golang:1.27.4-bookworm AS builder

# Install build tools (git for VCS stamping; no gcc needed — CGO disabled).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the Rampart source
COPY . ./rampart/

# Pure-Go build (CGO disabled — ORT excised 2026-11-26, ML withdrawn)
WORKDIR /build/rampart
ENV CGO_ENABLED=0
RUN go build \
    -ldflags="-s -w" \
    -o /rampart ./cmd/rampart

# Production stage: minimal Debian bookworm-slim.
FROM debian:bookworm-slim

# Install runtime dependencies: ca-certificates (TLS).
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -s /usr/sbin/nologin appuser

# Copy binary
COPY --from=builder /rampart /usr/local/bin/rampart

# NOTE: No ML model is shipped. Neural ML detection was withdrawn 2026-11-23
# (see docs/ML-WITHDRAWN.md). The container runs deterministic detection only.

# Copy default config
COPY configs/default.json /etc/aegisgate-rampart/config.json

# Create writable data directories
RUN mkdir -p /data/certs /data/audit /data/logs && \
    chown -R appuser:appuser /data

# Run as non-root user
USER appuser

EXPOSE 8080

# Single writable volume for audit logs, certificates, etc.
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/rampart"]
CMD ["--port", "8080"]