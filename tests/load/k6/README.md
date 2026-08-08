# AegisGate Rampart — k6 Load Test Suite

Break/crash/stress/endurance tests for the Rampart local HTTPS MITM proxy.

**Key principle: Rampart runs locally on user machines. It MUST NOT crash under any load.**

A rate-limited 429 response is acceptable. A process crash is a failure.

## Test Suite

| Test | File | Purpose | Duration | Peak VUs |
|------|------|---------|----------|----------|
| **Stress** | `stress-test.js` | Graduated load (5→100 VUs), baseline performance | ~90s | 100 |
| **Break** | `break-test.js` | Find the ceiling — 1x→20x progressive load | ~5min | 1000 |
| **Crush** | `crush-test.js` | Sequential crush with recovery verification | ~7min | 2000 |
| **Malformed Input** | `malformed-input-test.js` | Invalid JSON, oversized payloads, binary, unicode, HTTP abuse | ~4min | 500 |
| **Rate Limit** | `rate-limit-test.js` | Verify rate limiter enforcement and recovery | ~2.5min | 100 |
| **Connection Flood** | `connection-flood-test.js` | Rapid open/close, connection storms, sustained concurrent | ~3min | 500 |
| **Endurance** | `endurance-test.js` | 5-minute sustained load for memory leak detection | 5min | 50 |

## Prerequisites

1. Install [k6](https://k6.io/docs/get-started/installation/):
   ```bash
   # macOS
   brew install k6
   # Ubuntu/Debian
   sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C947A3B8E6
   sudo add-apt-repository 'deb https://k6.io/repos/deb stable main'
   sudo apt update && sudo apt install k6
   ```

2. Start Rampart with appropriate rate limits:
   ```bash
   # For stress/break/crush tests — high rate limit
   ./rampart --rate-limit 10000

   # For rate limit verification — default 30 RPS
   ./rampart
   ```

3. Verify Rampart is running:
   ```bash
   curl -s http://127.0.0.1:8080/stats | jq .
   ```

## Quick Start

```bash
# Run all tests (recommended order)
cd tests/load/k6

# 1. Baseline performance
k6 run stress-test.js

# 2. Find the ceiling
k6 run break-test.js

# 3. Progressive crush with recovery
k6 run crush-test.js

# 4. Malformed input resilience
k6 run malformed-input-test.js

# 5. Rate limit verification
k6 run rate-limit-test.js

# 6. Connection flood resilience
k6 run connection-flood-test.js

# 7. Endurance (5 min)
k6 run endurance-test.js
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RAMPART_URL` | `http://127.0.0.1:8080` | Rampart proxy URL |

Example:
```bash
k6 run --env RAMPART_URL=http://192.168.1.100:8080 break-test.js
```

## Results

Each test writes results to `tests/load/k6/results/` and stdout. Key metrics:

- **crash_rate**: Must be 0%. Any connection-refused = potential crash.
- **error_rate**: Acceptable if mostly 429s (rate limiting).
- **latency p95/p99**: Must stay under thresholds.
- **recovery_rate**: After crush phase, Rampart must respond normally.

## Interpreting Results

### ✅ PASS Criteria
- **Zero crashes** — `crash_rate` must be 0%
- **Recovery** — After peak load, Rampart responds within normal latency
- **No 5xx errors** — Server errors indicate bugs, not expected behavior
- **Graceful degradation** — Under extreme load, 429 > 500

### ⚠️ Warning Signs
- Increasing latency over time (memory leak)
- 5xx errors under moderate load (bugs)
- Connection refused after load drops (process crash)

### ❌ FAIL Criteria
- Any connection-refused errors (process crashed)
- 5xx errors on valid requests (server bugs)
- Increasing latency that doesn't recover (memory/resource leak)

## Monitoring During Tests

Watch Rampart's memory and goroutines:
```bash
# Process memory
watch -n 1 'ps aux | grep rampart | grep -v grep'

# If pprof is enabled
go tool pprof http://localhost:8080/debug/pprof/heap
go tool pprof http://localhost:8080/debug/pprof/goroutine
```

## Test Design Philosophy

These tests are adapted from the Platform's k6 test suite but focus on
**local proxy resilience** rather than **cloud service scalability**:

1. **Local proxy ≠ cloud service**: A local proxy must never crash because
   there's no load balancer or auto-scaling to recover. If Rampart crashes,
   the user's protection stops.

2. **Rate limiting is a feature, not a bug**: 429 responses are expected
   under high load. The key is that Rampart keeps running and recovers.

3. **Malformed input is reality**: User traffic can be anything. A local
   proxy sees all kinds of weird traffic — it must handle it gracefully.

4. **Connection floods happen**: Browsers open many connections, AI tools
   make rapid API calls, and network conditions vary. Rampart must cope.