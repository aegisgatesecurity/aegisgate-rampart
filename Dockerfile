# SPDX-License-Identifier: Apache-2.0
# AegisGate Rampart — Multi-stage Production Build
# =========================================================================
# Build:  docker build -t aegisgate-rampart:latest .
# Run:    docker run -p 8080:8080 aegisgate-rampart:latest
#
# ML-enabled build (CGO_ENABLED=1, ONNX Runtime v1.29.0 included).
# Includes CNN-BiLSTM threat detector (v13 model) for neural detection.
# If the model is absent at runtime, falls back to heuristic detection.
#
# Uses Debian bookworm-slim base (not Alpine) because onnxruntime prebuilt
# Linux shared libraries require glibc (ld-linux-x86-64.so.2). Alpine's musl
# libc cannot load them. The ~67MB size increase over Alpine is acceptable
# for a production security tool.
#
# Hardening:
#   - Production stage runs as non-root via USER appuser.
#   - Only ca-certificates and libstdc++6 added (minimal attack surface).
# =========================================================================

# Builder stage: Go 1.27 on Debian bookworm with ONNX Runtime v1.29.0.
FROM golang:1.27.1-bookworm AS builder

# Install build tools + download ONNX Runtime v1.29.0
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates gcc wget && \
    rm -rf /var/lib/apt/lists/* && \
    wget -q https://github.com/microsoft/onnxruntime/releases/download/v1.29.0/onnxruntime-linux-x64-1.29.0.tgz && \
    tar -xzf onnxruntime-linux-x64-1.29.0.tgz && \
    cp onnxruntime-linux-x64-1.29.0/lib/*.so /usr/lib/ && \
    cp -r onnxruntime-linux-x64-1.29.0/include/* /usr/include/ && \
    rm -rf onnxruntime-linux-x64-1.29.0.tgz onnxruntime-linux-x64-1.29.0

WORKDIR /build

# Copy the Rampart source
COPY . ./rampart/

# Build with CGO enabled for ONNX Runtime support
WORKDIR /build/rampart
ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-I/usr/include"
ENV CGO_LDFLAGS="-L/usr/lib -lonnxruntime"
RUN go build \
    -ldflags="-s -w" \
    -o /rampart ./cmd/rampart

# Production stage: minimal Debian bookworm-slim with ONNX Runtime.
FROM debian:bookworm-slim

# Install runtime dependencies: ca-certificates (TLS), libstdc++6 (for ONNX).
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        ca-certificates libstdc++6 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -s /usr/sbin/nologin appuser

# Copy binary
COPY --from=builder /rampart /usr/local/bin/rampart

# Copy ONNX Runtime library
COPY --from=builder /usr/lib/libonnxruntime.so* /usr/lib/
RUN ln -sf /usr/lib/libonnxruntime.so /usr/lib/onnxruntime.so

# Copy ML model (v13 CNN-BiLSTM threat detection model)
COPY --from=builder /build/rampart/models/threat_cnn_bilstm.onnx /opt/aegisgate-rampart/models/threat_cnn_bilstm.onnx

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