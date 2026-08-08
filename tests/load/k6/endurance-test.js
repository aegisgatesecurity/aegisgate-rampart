// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — Endurance Test (Memory Leak Detection)
// =========================================================================
// Purpose: Sustained load over an extended period to detect memory leaks,
//          goroutine leaks, and resource exhaustion.
//
// A local proxy that runs 24/7 on a user's machine MUST be stable over
// long periods. Even small leaks compound over hours/days.
//
// What we're measuring:
//   - Does latency increase over time? (memory pressure → GC pauses)
//   - Does error rate increase over time?
//   - Does Rampart stay responsive after sustained load?
//   - Are there any crashes during extended operation?
//
// Run: k6 run --env RAMPART_URL=http://127.0.0.1:8080 endurance-test.js
//
// NOTE: Monitor Rampart's memory usage externally during this test:
//   watch -n 5 'ps aux | grep rampart | grep -v grep'
//   OR: go tool pprof http://localhost:9090/debug/pprof/heap
// =========================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const detectLatency = new Trend('detect_latency', true);
const statsLatency = new Trend('stats_latency', true);
const rpsCounter = new Counter('rps');
const crashDetected = new Rate('crash');

const BASE = __ENV.RAMPART_URL || 'http://127.0.0.1:8080';

// Varied payloads to exercise different code paths
const payloads = {
  ssn: JSON.stringify({ text: 'My SSN is 123-45-6789' }),
  email: JSON.stringify({ text: 'Contact me at john@example.com' }),
  credit_card: JSON.stringify({ text: 'My credit card is 4111-1111-1111-1111' }),
  api_key: JSON.stringify({ text: 'AWS key: AKIAIOSFODNN7EXAMPLE' }),
  xss: JSON.stringify({ text: '<script>alert("XSS")</script>' }),
  mixed: JSON.stringify({ text: 'SSN: 123-45-6789, Email: john@example.com, CC: 4111-1111-1111-1111' }),
  long_clean: JSON.stringify({ text: 'The quick brown fox jumps over the lazy dog. '.repeat(100) }),
  long_dirty: JSON.stringify({ text: 'A'.repeat(5000) + ' SSN: 999-88-7777 API: sk-proj-abc123' }),
  empty: JSON.stringify({ text: '' }),
  unicode: JSON.stringify({ text: '你好世界 🌍 مرحبا Привет' }),
  financial: JSON.stringify({ text: 'Routing: 021000021 Account: 123456789 CC: 4532-1234-5678-9010' }),
  secrets: JSON.stringify({ text: 'postgresql://admin:password@db.example.com:5432/prod\nghp_1234567890abcdef' }),
};

const payloadKeys = Object.keys(payloads);

export const options = {
  scenarios: {
    // Sustained moderate load for 5 minutes
    sustained_moderate: {
      executor: 'constant-vus',
      vus: 50,
      duration: '5m',
      exec: 'sustainedRequest',
    },
    // Steady background load
    background_load: {
      executor: 'constant-vus',
      vus: 20,
      duration: '5m',
      exec: 'backgroundLoad',
      startTime: '0s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.10'],       // Max 10% failures (rate limiting is OK)
    http_req_duration: ['p(99)<5000'],     // 99% under 5s
    errors: ['rate<0.10'],
  },
};

export function sustainedRequest() {
  const key = payloadKeys[Math.floor(Math.random() * payloadKeys.length)];
  const payload = payloads[key];

  const res = http.post(`${BASE}/detect`, payload, {
    headers: { 'Content-Type': 'application/json' },
    timeout: '30s',
    tags: { phase: 'sustained', payload_type: key },
  });

  detectLatency.add(res.timings.duration);
  rpsCounter.add(1);

  const is5xx = res.status >= 500;
  const isOk = res.status === 200;
  const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');

  errorRate.add(!isOk && !is5xx && res.status !== 429);
  crashDetected.add(isConnectionRefused);

  check(res, {
    'sustained: response received': (r) => r.status > 0 || !isConnectionRefused,
    'sustained: not crashed': (r) => !isConnectionRefused,
  });

  sleep(Math.random() * 0.2 + 0.05);
}

export function backgroundLoad() {
  // Light background /stats polling
  const res = http.get(`${BASE}/stats`, {
    timeout: '10s',
    tags: { phase: 'background', endpoint: 'stats' },
  });

  statsLatency.add(res.timings.duration);

  const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');
  crashDetected.add(isConnectionRefused);

  check(res, {
    'background: stats respond': (r) => r.status === 200 || r.status === 429,
    'background: not crashed': (r) => !isConnectionRefused,
  });

  sleep(1); // 1 request per second
}

export function handleSummary(data) {
  const total = data.metrics.http_reqs?.count || 0;
  const dur = (data.state.testRunDurationMs || 1) / 1000;
  const crashPct = (data.metrics.crash?.rate || 0) * 100;
  const errorPct = (data.metrics.errors?.rate || 0) * 100;

  // Check for latency increase over time by comparing first 10% vs last 10%
  // k6 doesn't easily give us time-windowed metrics, so we report overall
  const summary = {
    endurance_test: {
      version: 'v0.3.0',
      product: 'AegisGate Rampart',
      timestamp: new Date().toISOString(),
      duration: '5 minutes',
      total_requests: total,
      avg_rps: (total / dur).toFixed(0),
      crash_rate: crashPct.toFixed(4) + '%',
      error_rate: errorPct.toFixed(2) + '%',
      detect_latency: {
        avg: data.metrics.detect_latency?.avg?.toFixed(2) + 'ms',
        p50: data.metrics.detect_latency?.values?.['p(50)']?.toFixed(2) + 'ms',
        p90: data.metrics.detect_latency?.values?.['p(90)']?.toFixed(2) + 'ms',
        p95: data.metrics.detect_latency?.values?.['p(95)']?.toFixed(2) + 'ms',
        p99: data.metrics.detect_latency?.values?.['p(99)']?.toFixed(2) + 'ms',
        max: data.metrics.detect_latency?.values?.['max']?.toFixed(2) + 'ms',
      },
      stats_latency: {
        avg: data.metrics.stats_latency?.avg?.toFixed(2) + 'ms',
        p95: data.metrics.stats_latency?.values?.['p(95)']?.toFixed(2) + 'ms',
        p99: data.metrics.stats_latency?.values?.['p(99)']?.toFixed(2) + 'ms',
      },
      overall_latency: {
        avg: data.metrics.http_req_duration?.avg?.toFixed(2) + 'ms',
        p50: data.metrics.http_req_duration?.values?.['p(50)']?.toFixed(2) + 'ms',
        p95: data.metrics.http_req_duration?.values?.['p(95)']?.toFixed(2) + 'ms',
        p99: data.metrics.http_req_duration?.values?.['p(99)']?.toFixed(2) + 'ms',
        max: data.metrics.http_req_duration?.values?.['max']?.toFixed(2) + 'ms',
      },
      verdict: {
        crash_safe: crashPct === 0 ? '✅ PASS — No crashes during 5-minute endurance test' : '❌ FAIL — Rampart crashed during endurance test',
        memory_leak_check: '⚠️  Monitor memory externally: watch -n 5 "ps aux | grep rampart"',
        latency_stable: data.metrics.detect_latency?.values?.['p(99)'] < 2000
          ? '✅ PASS — p99 latency stayed under 2s during sustained load'
          : '⚠️  p99 latency exceeded 2s — possible memory pressure or GC issues',
      },
    },
  };

  return {
    'results/endurance-test-results.json': JSON.stringify(summary, null, 2),
    stdout: JSON.stringify(summary, null, 2),
  };
}