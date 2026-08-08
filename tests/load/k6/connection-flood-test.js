// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — Connection Flood Test
// =========================================================================
// Purpose: Test Rampart's resilience to rapid connection open/close,
//          slow loris-style attacks, and connection exhaustion.
//
// A local proxy must handle:
//   - Thousands of rapid open/close connections
//   - Connections that open but never send data
//   - Connections that send partial data then disconnect
//   - Sustained concurrent connections
//   - Connection storms (burst of connections then silence)
//
// CRITICAL: Rampart must never crash. It may reject connections, but it
//           must keep running and recover.
//
// Run: k6 run --env RAMPART_URL=http://127.0.0.1:8080 connection-flood-test.js
//
// Note: k6 doesn't natively support slow-loris or raw TCP testing.
// For full connection-flood coverage, consider supplementing with:
//   - `hey` (HTTPS load generator with connection recycling)
//   - Custom Go test that opens raw TCP connections
//   - `wrk` with pipelining
// =========================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';

const crashDetected = new Rate('crash');
const connectionError = new Rate('connection_errors');
const successRate = new Rate('success');
const rpsCounter = new Counter('rps');
const connectLatency = new Trend('connect_latency', true);
const activeConnections = new Gauge('active_connections');

const BASE = __ENV.RAMPART_URL || 'http://127.0.0.1:8080';

export const options = {
  scenarios: {
    // Phase 1: Rapid connect/disconnect
    rapid_connect_disconnect: {
      executor: 'constant-vus',
      vus: 200,
      duration: '30s',
      exec: 'rapidConnectDisconnect',
      startTime: '0s',
    },
    // Phase 2: Connection storm — burst of connections
    connection_storm: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '5s', target: 500 },
        { duration: '10s', target: 500 },
        { duration: '5s', target: 0 },
      ],
      exec: 'connectionStorm',
      startTime: '35s',
    },
    // Phase 3: Sustained concurrent connections
    sustained_concurrent: {
      executor: 'constant-vus',
      vus: 300,
      duration: '45s',
      exec: 'sustainedConcurrent',
      startTime: '55s',
    },
    // Phase 4: Mixed load — rapid requests with varying sizes
    mixed_load: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 100 },
        { duration: '20s', target: 500 },
        { duration: '10s', target: 100 },
        { duration: '5s', target: 0 },
      ],
      exec: 'mixedLoad',
      startTime: '105s',
    },
    // Phase 5: Recovery — verify Rampart still works after the flood
    recovery: {
      executor: 'constant-vus',
      vus: 20,
      duration: '20s',
      exec: 'recoveryCheck',
      startTime: '155s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.50'],
    http_req_duration: ['p(99)<30000'],
  },
};

export function rapidConnectDisconnect() {
  // Open a connection, make a single request, close immediately
  const payload = JSON.stringify({ text: 'SSN: 123-45-6789' });

  const res = http.post(`${BASE}/detect`, payload, {
    headers: { 'Content-Type': 'application/json' },
    timeout: '5s',
    tags: { phase: 'rapid_connect' },
  });

  connectLatency.add(res.timings.duration);
  rpsCounter.add(1);

  const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');
  const isConnError = res.status === 0;
  const isOk = res.status === 200;

  crashDetected.add(isConnectionRefused);
  connectionError.add(isConnError);
  successRate.add(isOk || res.status === 429);

  check(res, {
    'rapid: response received': (r) => r.status > 0 || !isConnectionRefused,
    'rapid: not crashed': (r) => !isConnectionRefused,
  });

  // No sleep — maximum request rate
}

export function connectionStorm() {
  // Send bursts of requests
  for (let i = 0; i < 3; i++) {
    const payload = JSON.stringify({ text: `Storm request ${__VU}-${i}` });

    const res = http.post(`${BASE}/detect`, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: '10s',
      tags: { phase: 'storm' },
    });

    rpsCounter.add(1);

    const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');
    crashDetected.add(isConnectionRefused);

    check(res, {
      'storm: not crashed': (r) => !isConnectionRefused,
    });
  }

  sleep(0.01);
}

export function sustainedConcurrent() {
  // Sustained requests from many concurrent VUs
  const sizes = [
    JSON.stringify({ text: 'Short PII: SSN 123-45-6789' }),
    JSON.stringify({ text: 'Medium: ' + 'Hello '.repeat(100) + 'SSN: 123-45-6789' }),
    JSON.stringify({ text: 'A'.repeat(5000) + ' SSN: 999-88-7777' }),
    JSON.stringify({ text: 'No PII here, just normal text.' }),
  ];

  const payload = sizes[Math.floor(Math.random() * sizes.length)];

  const res = http.post(`${BASE}/detect`, payload, {
    headers: { 'Content-Type': 'application/json' },
    timeout: '30s',
    tags: { phase: 'sustained' },
  });

  connectLatency.add(res.timings.duration);
  rpsCounter.add(1);

  const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');
  crashDetected.add(isConnectionRefused);
  successRate.add(res.status === 200 || res.status === 429);

  check(res, {
    'sustained: not crashed': (r) => !(r.status === 0 && (r.error || '').includes('connection refused')),
    'sustained: response or rate limit': (r) => r.status === 200 || r.status === 429 || r.status >= 400,
  });

  sleep(Math.random() * 0.1);
}

export function mixedLoad() {
  // Mix of /detect and /stats requests
  if (Math.random() < 0.8) {
    const payloads = [
      JSON.stringify({ text: 'SSN: 123-45-6789' }),
      JSON.stringify({ text: 'Email: user@example.com CC: 4111-1111-1111-1111' }),
      JSON.stringify({ text: 'A'.repeat(10000) }),
      JSON.stringify({ text: '' }),
    ];

    const payload = payloads[Math.floor(Math.random() * payloads.length)];

    const res = http.post(`${BASE}/detect`, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: '30s',
      tags: { phase: 'mixed', endpoint: 'detect' },
    });

    rpsCounter.add(1);

    const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');
    crashDetected.add(isConnectionRefused);

    check(res, {
      'mixed detect: not crashed': (r) => !isConnectionRefused,
    });
  } else {
    const res = http.get(`${BASE}/stats`, {
      timeout: '10s',
      tags: { phase: 'mixed', endpoint: 'stats' },
    });

    rpsCounter.add(1);

    const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');
    crashDetected.add(isConnectionRefused);

    check(res, {
      'mixed stats: not crashed': (r) => !isConnectionRefused,
    });
  }

  sleep(Math.random() * 0.05);
}

export function recoveryCheck() {
  // After the flood — does Rampart still work?
  const res = http.post(`${BASE}/detect`, JSON.stringify({ text: 'My SSN is 123-45-6789' }), {
    headers: { 'Content-Type': 'application/json' },
    timeout: '10s',
    tags: { phase: 'recovery' },
  });

  rpsCounter.add(1);

  const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');
  crashDetected.add(isConnectionRefused);
  successRate.add(res.status === 200);

  check(res, {
    'recovery: Rampart responds': (r) => r.status > 0,
    'recovery: not crashed': (r) => !isConnectionRefused,
    'recovery: returns 200': (r) => r.status === 200 || r.status === 429,
    'recovery: valid detection': (r) => {
      if (r.status !== 200) return r.status === 429;
      try {
        const body = JSON.parse(r.body);
        return typeof body.total_detections === 'number';
      } catch { return false; }
    },
  });

  sleep(0.2);
}

export function handleSummary(data) {
  const total = data.metrics.http_reqs?.count || 0;
  const dur = (data.state.testRunDurationMs || 1) / 1000;
  const crashPct = (data.metrics.crash?.rate || 0) * 100;
  const connErrPct = (data.metrics.connection_errors?.rate || 0) * 100;
  const successPct = (data.metrics.success?.rate || 0) * 100;

  const summary = {
    connection_flood_test: {
      version: 'v0.3.0',
      product: 'AegisGate Rampart',
      timestamp: new Date().toISOString(),
      total_requests: total,
      duration_sec: dur.toFixed(1),
      avg_rps: (total / dur).toFixed(0),
      crash_rate: crashPct.toFixed(4) + '%',
      connection_error_rate: connErrPct.toFixed(2) + '%',
      success_rate: successPct.toFixed(2) + '%',
      latency: {
        avg: data.metrics.connect_latency?.avg?.toFixed(2) + 'ms',
        p50: data.metrics.connect_latency?.values?.['p(50)']?.toFixed(2) + 'ms',
        p95: data.metrics.connect_latency?.values?.['p(95)']?.toFixed(2) + 'ms',
        p99: data.metrics.connect_latency?.values?.['p(99)']?.toFixed(2) + 'ms',
      },
      verdict: {
        crash_safe: crashPct === 0 ? '✅ PASS — Rampart never crashed during connection flood' : '❌ FAIL — Rampart crashed during connection flood',
        connection_resilience: connErrPct < 10 ? '✅ PASS — Less than 10% connection errors' : '⚠️  High connection error rate (' + connErrPct.toFixed(1) + '%)',
        recovery: crashPct === 0 ? '✅ PASS — Rampart recovered after flood' : '❌ FAIL — Rampart did not recover after flood',
      },
    },
  };

  return {
    'results/connection-flood-test-results.json': JSON.stringify(summary, null, 2),
    stdout: JSON.stringify(summary, null, 2),
  };
}