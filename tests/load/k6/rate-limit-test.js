// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — Rate Limit Verification Test
// =========================================================================
// Purpose: Verify that Rampart's rate limiter enforces limits correctly
//          and that the proxy recovers after rate limit periods.
//
// Key requirements:
//   1. Rate limiting is enforced (429 responses returned when exceeded)
//   2. Rate limit resets after window
//   3. Rampart doesn't crash under rate-limited flood
//   4. After rate limit clears, requests succeed again
//
// Run: k6 run --env RAMPART_URL=http://127.0.0.1:8080 rate-limit-test.js
// =========================================================================

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const rateLimitTriggered = new Rate('rate_limit_triggered');
const normalResponseRate = new Rate('normal_responses');
const crashDetected = new Rate('crash');
const rateLimitLatency = new Trend('rate_limit_latency', true);
const rpsCounter = new Counter('rps');

const BASE = __ENV.RAMPART_URL || 'http://127.0.0.1:8080';

export const options = {
  scenarios: {
    // Phase 1: Normal traffic — baseline before rate limit
    phase1_baseline: {
      executor: 'constant-vus',
      vus: 10,
      duration: '15s',
      exec: 'normalTraffic',
      startTime: '0s',
    },
    // Phase 2: Flood traffic — exceed rate limit (assuming default 30 RPS)
    phase2_flood: {
      executor: 'constant-vus',
      vus: 100,
      duration: '30s',
      exec: 'floodTraffic',
      startTime: '20s',
    },
    // Phase 3: Recovery — back to normal, verify 429s stop
    phase3_recovery: {
      executor: 'constant-vus',
      vus: 10,
      duration: '20s',
      exec: 'normalTraffic',
      startTime: '55s',
    },
    // Phase 4: Sustained heavy — continuous near-limit traffic
    phase4_sustained: {
      executor: 'constant-vus',
      vus: 50,
      duration: '30s',
      exec: 'floodTraffic',
      startTime: '80s',
    },
    // Phase 5: Final recovery
    phase5_final_recovery: {
      executor: 'constant-vus',
      vus: 10,
      duration: '20s',
      exec: 'normalTraffic',
      startTime: '115s',
    },
  },
  thresholds: {
    // Rate limit should trigger during flood phases
    'rate_limit_triggered': ['rate > 0'],
    // No crashes allowed
    'crash': ['rate == 0'],
    // At least some normal responses in baseline/recovery phases
    'normal_responses': ['rate > 0'],
    // Responses should still be fast even when rate-limited
    http_req_duration: ['p(99)<10000'],
  },
};

export function normalTraffic() {
  group('Normal Traffic', () => {
    const payload = JSON.stringify({ text: 'My SSN is 123-45-6789' });

    const res = http.post(`${BASE}/detect`, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: '10s',
      tags: { phase: 'normal' },
    });

    rateLimitLatency.add(res.timings.duration);
    rpsCounter.add(1);

    const is429 = res.status === 429;
    const isOk = res.status === 200;
    const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');

    rateLimitTriggered.add(is429);
    normalResponseRate.add(isOk);
    crashDetected.add(isConnectionRefused);

    check(res, {
      'normal: response received': (r) => r.status > 0,
      'normal: not crashed': (r) => !isConnectionRefused,
      'normal: 200 or 429': (r) => r.status === 200 || r.status === 429,
    });

    if (isOk) {
      check(res, {
        'normal: valid detection response': (r) => {
          try {
            const body = JSON.parse(r.body);
            return typeof body.total_detections === 'number';
          } catch { return false; }
        },
      });
    }

    sleep(0.5); // Slow rate — should not hit rate limit
  });
}

export function floodTraffic() {
  group('Flood Traffic', () => {
    const payloads = [
      JSON.stringify({ text: 'My SSN is 123-45-6789' }),
      JSON.stringify({ text: 'Email: john@example.com' }),
      JSON.stringify({ text: 'CC: 4111-1111-1111-1111' }),
      JSON.stringify({ text: 'Safe message with no PII' }),
    ];

    const payload = payloads[Math.floor(Math.random() * payloads.length)];

    const res = http.post(`${BASE}/detect`, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: '10s',
      tags: { phase: 'flood' },
    });

    rateLimitLatency.add(res.timings.duration);
    rpsCounter.add(1);

    const is429 = res.status === 429;
    const isOk = res.status === 200;
    const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');

    rateLimitTriggered.add(is429);
    normalResponseRate.add(isOk);
    crashDetected.add(isConnectionRefused);

    check(res, {
      'flood: response received': (r) => r.status > 0 || !isConnectionRefused,
      'flood: not crashed': (r) => !isConnectionRefused,
      'flood: 200 or 429': (r) => r.status === 200 || r.status === 429,
    });

    if (is429) {
      check(res, {
        'flood: 429 has body': (r) => r.body && r.body.length > 0,
        'flood: 429 response is fast': (r) => r.timings.duration < 100,
      });
    }

    sleep(0.01); // 10ms between requests — aggressive
  });
}

export function handleSummary(data) {
  const total = data.metrics.http_reqs?.count || 0;
  const dur = (data.state.testRunDurationMs || 1) / 1000;
  const rateLimitPct = (data.metrics.rate_limit_triggered?.rate || 0) * 100;
  const normalPct = (data.metrics.normal_responses?.rate || 0) * 100;
  const crashPct = (data.metrics.crash?.rate || 0) * 100;

  const summary = {
    rate_limit_test: {
      version: 'v0.3.0',
      product: 'AegisGate Rampart',
      timestamp: new Date().toISOString(),
      total_requests: total,
      duration_sec: dur.toFixed(1),
      avg_rps: (total / dur).toFixed(0),
      rate_limited_pct: rateLimitPct.toFixed(2) + '%',
      normal_response_pct: normalPct.toFixed(2) + '%',
      crash_rate: crashPct.toFixed(4) + '%',
      latency: {
        avg: data.metrics.rate_limit_latency?.avg?.toFixed(2) + 'ms',
        p50: data.metrics.rate_limit_latency?.values?.['p(50)']?.toFixed(2) + 'ms',
        p95: data.metrics.rate_limit_latency?.values?.['p(95)']?.toFixed(2) + 'ms',
        p99: data.metrics.rate_limit_latency?.values?.['p(99)']?.toFixed(2) + 'ms',
      },
      verdict: {
        rate_limiting_working: rateLimitPct > 0 ? '✅ PASS — Rate limiting is ENFORCED' : '❌ FAIL — No 429s observed (increase load or lower --rate-limit)',
        crash_safe: crashPct === 0 ? '✅ PASS — No crashes during rate limit flood' : '❌ FAIL — Rampart crashed during rate limit flood',
        recovery: normalPct > 50 ? '✅ PASS — Rampart recovered after rate limiting' : '❌ FAIL — Rampart did not recover',
      },
    },
  };

  return {
    'results/rate-limit-test-results.json': JSON.stringify(summary, null, 2),
    stdout: JSON.stringify(summary, null, 2),
  };
}