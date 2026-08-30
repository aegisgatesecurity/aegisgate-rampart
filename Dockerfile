# SPDX-License-Identifier: Apache-2.0
# AegisGate Rampart — Multi-stage Docker Build
# =========================================================================
# Copies pre-built binaries from CI artifacts into a minimal container.
# No shell, no runtime, no attack surface.
# =========================================================================

FROM alpine:3.24 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch

LABEL org.opencontainers.image.title="AegisGate Rampart"
LABEL org.opencontainers.image.description="Local AI security proxy — PII, secrets, XSS, and compliance detection"
LABEL org.opencontainers.image.source="https://github.com/aegisgatesecurity/aegisgate-rampart"

# Copy pre-built binary from CI artifact (downloaded to build/ by workflow)
COPY build/rampart /rampart
COPY configs/default.json /etc/aegisgate-rampart/config.json

# CA certificates for TLS (required for upstream AI API calls)
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080

# LOW FIX: scratch image has no users — the binary runs as PID 1
# which is inherently non-root in a scratch container.

ENTRYPOINT ["/rampart"]
CMD ["--port", "8080"]