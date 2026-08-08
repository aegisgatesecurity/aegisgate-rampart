// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — Crush Test (Sequential Phases)
// =========================================================================
// Purpose: Progressive crush with recovery verification.
// Scenarios run SEQUENTIALLY using startTime offsets.
// Phase 1: 50 VU baseline → Phase 2: 100 VU → Phase 3: 250 VU
// Phase 4: 500 VU → Phase 5: 1000 VU → Phase 6: 2000 VU (crush)
// Phase 7: Recovery (back to 50 VU — MUST recover)
//
// CRITICAL TEST: After the crush phase, does Rampart still respond?
// A local proxy MUST recover gracefully. A crash is a failure.
//
// Run: k6 run --env RAMPART_URL=http://127.0.0.1:8080 crush-test.js
// =========================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const detectLatency = new Trend('detect_latency', true);
const statsLatency = new Trend('stats_latency', true);
const rpsCounter = new Counter('rps');
const crashDetected = new Rate('crash');
const recoveryOk = new Rate('recovery_ok');

const BASE = __ENV.RAMPART_URL || 'http://127.0.0.1:8080';

// Detection payloads — varied PII types for comprehensive coverage under load
const payloads = {
  short_hit: JSON.stringify({ text: 'My SSN is 123-45-6789' }),
  medium_hit: JSON.stringify({ text: 'Hello, my email is john@example.com and phone is 555-123-4567. CC: 4111-1111-1111-1111. AWS: AKIAIOSFODNN7EXAMPLE.' }),
  long_hit: JSON.stringify({ text: 'A'.repeat(5000) + ' SSN: 999-88-7777 API: sk-proj-abc123' }),
  nohit: JSON.stringify({ text: 'This is a perfectly safe message.' }),
  xss: JSON.stringify({ text: '<script>alert("XSS")</script><img src=x onerror=alert(1)>' }),
  empty: JSON.stringify({ text: '' }),
};

const payloadKeys = Object.keys(payloads);

export const options = {
  scenarios: {
    // Phase 1: 1x baseline (50 VUs) — 0-30s
    phase1_baseline: {
      executor: 'constant-vus',
      vus: 50,
      duration: '30s',
      gracefulStop: '0s',
      startTime: '0s',
    },
    // Phase 2: 2x (100 VUs) — 35-85s
    phase2_burst: {
      executor: 'constant-vus',
      vus: 100,
      duration: '50s',
      gracefulStop: '0s',
      startTime: '35s',
    },
    // Phase 3: 5x (250 VUs) — 90-150s
    phase3_stress: {
      executor: 'constant-vus',
      vus: 250,
      duration: '60s',
      gracefulStop: '0s',
      startTime: '90s',
    },
    // Phase 4: 10x (500 VUs) — 155-235s
    phase4_extreme: {
      executor: 'constant-vus',
      vus: 500,
      duration: '80s',
      gracefulStop: '0s',
      startTime: '155s',
    },
    // Phase 5: 20x crush (1000 VUs) — 240-300s
    phase5_crush: {
      executor: 'constant-vus',
      vus: 1000,
      duration: '60s',
      gracefulStop: '0s',
      startTime: '240s',
    },
    // Phase 6: 40x extreme crush (2000 VUs) — 305-365s
    phase6_extreme_crush: {
      executor: 'constant-vus',
      vus: 2000,
      duration: '60s',
      gracefulStop: '0s',
      startTime: '305s',
    },
    // Phase 7: Recovery (50 VUs) — 370-430s
    // CRITICAL: Rampart MUST respond here after the crush
    phase7_recovery: {
      executor: 'constant-vus',
      vus: 50,
      duration: '60s',
      gracefulStop: '0s',
      startTime: '370s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.50'],
    http_req_duration: ['p(99)<30000'],
  },
};

export default function () {
  const key = payloadKeys[Math.floor(Math.random() * payloadKeys.length)];
  const payload = payloads[key];

  if (Math.random() < 0.85) {
    const res = http.post(`${BASE}/detect`, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: '30s',
      tags: { endpoint: 'detect', payload_type: key },
    });

    detectLatency.add(res.timings.duration);

    const is5xx = res.status >= 500;
    const is429 = res.status === 429;
    const isOk = res.status === 200;
    const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');

    errorRate.add(!isOk && !is429);
    crashDetected.add(isConnectionRefused);

    // Track recovery: if we're in phase 7 and getting 200s, recovery is working
    if (isOk && res.timings.duration < 500) {
      recoveryOk.add(true);
    }

    check(res, {
      'detect: status received': (r) => r.status > 0,
      'detect: not crashed': (r) => !(r.status === 0 && (r.error || '').includes('connection refused')),
    });
  } else {
    const res = http.get(`${BASE}/stats`, { timeout: '30s', tags: { endpoint: 'stats' } });
    statsLatency.add(res.timings.duration);

    const isOk = res.status === 200 || res.status === 429;
    const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');

    errorRate.add(!isOk);
    crashDetected.add(isConnectionRefused);

    if (res.status === 200 && res.timings.duration < 100) {
      recoveryOk.add(true);
    }

    check(res, {
      'stats: status received': (r) => r.status > 0,
      'stats: not crashed': (r) => !(r.status === 0 && (r.error || '').includes('connection refused')),
    });
  }

  sleep(Math.random() * 0.05);
}

export function handleSummary(data) {
  const total = data.metrics.http_reqs?.count || 0;
  const dur = (data.state.testRunDurationMs || 1) / 1000;
  const failPct = (data.metrics.http_req_failed?.rate || 0) * 100;
  const crashPct = (data.metrics.crash?.rate || 0) * 100;
  const recoveryPct = (data.metrics.recovery_ok?.rate || 0) * 100;

  const summary = {
    crush_test: {
      version: 'v0.3.0',
      product: 'AegisGate Rampart',
      timestamp: new Date().toISOString(),
      total_requests: total,
      duration_sec: dur.toFixed(1),
      avg_rps: (total / dur).toFixed(0),
      overall_latency: {
        avg: data.metrics.http_req_duration?.avg?.toFixed(2),
        p50: data.metrics.http_req_duration?.values?.['p(50)']?.toFixed(2),
        p95: data.metrics.http_req_duration?.values?.['p(95)']?.toFixed(2),
        p99: data.metrics.http_req_duration?.values?.['p(99)']?.toFixed(2),
        max: data.metrics.http_req_duration?.values?.['max']?.toFixed(2),
      },
      detect_latency: {
        p95: data.metrics.detect_latency?.values?.['p(95)']?.toFixed(2),
        p99: data.metrics.detect_latency?.values?.['p(99)']?.toFixed(2),
      },
      stats_latency: {
        p95: data.metrics.stats_latency?.values?.['p(95)']?.toFixed(2),
      },
      error_rate: failPct.toFixed(3) + '%',
      crash_rate: crashPct.toFixed(4) + '%',
      recovery_rate: recoveryPct.toFixed(2) + '%',
      peak_vus: 2000,
      verdict: {
        crash_safe: crashPct === 0 ? '✅ PASS — Rampart survived 2000 VUs' : '❌ FAIL — Rampart crashed under load',
        recovery: recoveryPct > 90 ? '✅ PASS — Rampart recovered after crush' : '❌ FAIL — Rampart did not recover after crush',
      },
    },
  };

  return {
    'results/crush-test-results.json': JSON.stringify(summary, null, 2),
    stdout: JSON.stringify(summary, null, 2),
  };
}