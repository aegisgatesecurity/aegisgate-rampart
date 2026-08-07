# SPDX-License-Identifier: Apache-2.0
# AegisGate Rampart — Multi-stage Docker Build
# =========================================================================
# Produces a minimal scratch container with the rampart binary.
# No shell, no runtime, no attack surface.
# =========================================================================

FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /build

# Dependency caching layer
COPY go.mod go.sum ./
RUN go mod download

# Source layer
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags "-s -w -X main.versionFlag=$VERSION" \
    -o /rampart ./cmd/rampart/

# Minimal scratch container
FROM scratch

LABEL org.opencontainers.image.title="AegisGate Rampart"
LABEL org.opencontainers.image.description="Local AI security proxy — PII, secrets, XSS, and compliance detection"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/aegisgatesecurity/aegisgate-rampart"

# Copy binary and default config
COPY --from=builder /rampart /rampart
COPY configs/default.json /etc/aegisgate-rampart/config.json

# CA certificates for TLS (required for upstream AI API calls)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080

ENTRYPOINT ["/rampart"]
CMD ["--port", "8080"]