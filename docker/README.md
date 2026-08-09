# Docker Development Environment

This directory contains Docker configuration for local Rampart development.

## Quick Start

### Start Development Environment

```bash
# Start with hot-reload enabled
make docker-dev

# Or using docker-compose directly
docker-compose -f docker-compose.dev.yml up
```

This will:
- Build the development container with Go 1.21+
- Mount your source code for hot-reload
- Start Rampart with `air` for automatic rebuilds on file changes
- Expose port 8080 (proxy) and 6060 (pprof)

### Run Tests in Docker

```bash
# Run all tests with race detector
make docker-test

# Or directly
docker-compose -f docker-compose.dev.yml run --rm test
```

### Run Linter

```bash
make docker-lint
```

### Access Shell

```bash
make docker-shell
```

## Mock AI API

For local testing without hitting real AI APIs, use the mock API:

```bash
# Start mock API endpoints
make mock-api

# Or with docker-compose
docker-compose -f docker-compose.dev.yml --profile mock up mock-ai-api
```

The mock API simulates:
- OpenAI Chat Completions (`/v1/chat/completions`)
- OpenAI Completions (`/v1/completions`)
- Anthropic Completions (`/v1/complete`)
- Google AI GenerateContent (`/v1/models/gemini-pro:generateContent`)

### Testing with Mock API

```bash
# Start Rampart
rampart --port 8080

# Send test request through proxy
curl -x http://localhost:8080 \
  http://localhost:9090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Configuration

### docker-compose.dev.yml

Main compose file with services:
- `rampart`: Main development container
- `test`: Test runner (on-demand)
- `lint`: Linter (on-demand)
- `mock-ai-api`: Mock AI endpoints (optional profile)

### Dockerfile.dev

Development Dockerfile with:
- Go 1.21+ (configurable via build arg)
- Hot-reload tool (`air`)
- Linter (`golangci-lint`)
- Test tools (`gotestsum`)
- Debug symbols enabled

### .air.toml

Configuration for hot-reload:
- Watches `cmd/`, `pkg/`, `internal/` directories
- Rebuilds on `.go` file changes
- 1 second delay to prevent rapid rebuilds
- Color-coded output

## Volumes

- **Source code**: Mounted from host for hot-reload
- **Go module cache**: Persistent volume (`rampart-go-mod-cache`)
- **Build output**: Mounted to `./bin` on host

## Network

- **rampart-dev-network**: Bridge network for inter-service communication
- **Port 8080**: Proxy port (host → container)
- **Port 6060**: pprof debug port (optional)
- **Port 9090**: Mock API port (when using mock profile)

## Cleanup

```bash
# Stop containers and remove volumes
make docker-clean

# Or manually
docker-compose -f docker-compose.dev.yml down -v
docker system prune -f
```

## Troubleshooting

### Hot-reload not working

Ensure file changes are detected:
```bash
docker-compose -f docker-compose.dev.yml logs -f rampart
```

### Port conflicts

If port 8080 is in use:
```bash
# Check what's using the port
lsof -i :8080

# Or change proxy port in config
```

### Build failures in container

Rebuild from scratch:
```bash
docker-compose -f docker-compose.dev.yml build --no-cache
```

### Permission issues

Fix file permissions:
```bash
sudo chown -R $(whoami) bin/ tmp/
```

## Production vs Development

**⚠️ This development setup is NOT for production use.**

For production deployments, see:
- `packaging/debian/` - Debian/Ubuntu packages
- `packaging/redhat/` - RPM packages
- `packaging/homebrew/` - Homebrew formula
- `Makefile.packaging` - Build automation

Production images should:
- Use multi-stage builds
- Run as non-root user
- Include only runtime dependencies
- Have security scanning enabled

---

**Last updated:** August 8, 2026  
**Version:** 1.0 (v0.5.1 release)
