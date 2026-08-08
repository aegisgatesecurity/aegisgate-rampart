// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — Break Test
// =========================================================================
// Purpose: Find the actual ceiling. Push until latency degrades or errors appear.
// Strategy: Progressive load multiplier — 1x, 2x, 5x, 10x, 20x baseline —
//           then sustained ceiling hold and recovery.
//
// Key question for a LOCAL proxy: Does the process crash?
// If Rampart runs on a user's machine, it MUST survive any load.
// A 429 rate-limit response is acceptable. A crash is not.
//
// What we're measuring:
//   - At what VU count does p95 exceed 200ms?
//   - At what VU count does p99 exceed 1s?
//   - At what VU count do we see the first 5xx error?
//   - What's the maximum sustainable RPS before degradation?
//   - Does the process recover when load drops?
//   - Does Rampart stay alive after the crush phase?
//
// Run: k6 run --env RAMPART_URL=http://127.0.0.1:8080 break-test.js
// =========================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const detectLatency = new Trend('detect_latency', true);
const statsLatency = new Trend('stats_latency', true);
const rpsCounter = new Counter('rps');
const degradation = new Rate('degraded');    // p95 > 200ms
const critical = new Rate('critical');        // p95 > 1000ms or 5xx
const crashDetected = new Rate('crash');      // connection refused = possible crash

const BASE = __ENV.RAMPART_URL || 'http://127.0.0.1:8080';

// Realistic detection payloads with varying sizes and PII types
const payloads = {
  // PII hit: short
  short_hit: JSON.stringify({ text: 'My SSN is 123-45-6789' }),

  // PII hit: medium — multiple detections
  medium_hit: JSON.stringify({ text: 'Hello, I need help with my account. My email is john@example.com and my phone is 555-123-4567. Also my credit card is 4111-1111-1111-1111. Can you help me reset my password? I also have an AWS key: AKIAIOSFODNN7EXAMPLE.' }),

  // PII hit: long — stress the detector with a large payload
  long_hit: JSON.stringify({ text: 'A'.repeat(5000) + ' My SSN is 999-88-7777 and my API key is sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz.' }),

  // No hit: short — exercises the fast path
  short_nohit: JSON.stringify({ text: 'This is a perfectly safe message with no sensitive data.' }),

  // No hit: long — exercises the fast path on a large payload
  long_nohit: JSON.stringify({ text: 'The quick brown fox jumps over the lazy dog. '.repeat(200) }),

  // XSS hit — exercises XSS detector
  xss_hit: JSON.stringify({ text: '<script>alert("XSS")</script>Hello <b>world</b><img src=x onerror=alert(1)>' }),

  // Secrets hit — exercises secrets detector
  secrets_hit: JSON.stringify({ text: 'Database URL: postgresql://admin:supersecretpassword@db.example.com:5432/prod\nAWS Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nGitHub Token: ghp_1234567890abcdef1234567890abcdef1234' }),

  // Financial PII — exercises financial detector
  financial_hit: JSON.stringify({ text: 'My credit card is 4532-1234-5678-9010 and my bank routing number is 021000021 with account 123456789.' }),

  // Edge case: empty string
  empty: JSON.stringify({ text: '' }),

  // Edge case: unicode/mixed content
  unicode: JSON.stringify({ text: '你好世界 🌍 Привет мир مرحبا العالم हैलो दुनिया' }),
};

const payloadKeys = Object.keys(payloads);

export const options = {
  scenarios: {
    // Phase 1: 1x baseline (50 VUs)
    baseline_1x: {
      executor: 'constant-vus',
      vus: 50,
      duration: '30s',
      gracefulStop: '5s',
    },
    // Phase 2: 2x burst (100 VUs)
    burst_2x: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 100 },
        { duration: '30s', target: 100 },
        { duration: '10s', target: 0 },
      ],
      gracefulStop: '10s',
    },
    // Phase 3: 5x stress (250 VUs)
    stress_5x: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '15s', target: 250 },
        { duration: '30s', target: 250 },
        { duration: '15s', target: 0 },
      ],
      gracefulStop: '10s',
    },
    // Phase 4: 10x extreme (500 VUs)
    extreme_10x: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 500 },
        { duration: '30s', target: 500 },
        { duration: '20s', target: 0 },
      ],
      gracefulStop: '10s',
    },
    // Phase 5: 20x crush (1000 VUs) — find the breaking point
    crush_20x: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 1000 },
        { duration: '30s', target: 1000 },
        { duration: '30s', target: 0 },
      ],
      gracefulStop: '15s',
    },
  },
  thresholds: {
    // We DON'T assert strict thresholds — we're measuring where they break
    // The ONLY hard requirement: Rampart must not crash
    http_req_failed: ['rate<0.50'],          // Allow up to 50% failure (429s are OK)
    http_req_duration: ['p(99)<30000'],       // 30s max — just ensure we get responses
  },
};

export default function () {
  // 85% detect, 15% stats
  if (Math.random() < 0.85) {
    const key = payloadKeys[Math.floor(Math.random() * payloadKeys.length)];
    const payload = payloads[key];

    const res = http.post(`${BASE}/detect`, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: '30s',
      tags: { endpoint: 'detect', payload_type: key },
    });

    detectLatency.add(res.timings.duration);

    const is5xx = res.status >= 500;
    const is429 = res.status === 429;
    const isOk = res.status === 200;
    const isConnectionRefused = res.status === 0 && res.error.includes('connection refused');
    const duration = res.timings.duration;

    errorRate.add(!isOk && !is429);
    degradation.add(duration > 200);
    critical.add(duration > 1000 || is5xx);
    crashDetected.add(isConnectionRefused);

    check(res, {
      'detect: status received': (r) => r.status > 0,
      'detect: not server error': (r) => r.status < 500,
      'detect: not crashed': (r) => !isConnectionRefused,
    });

    // If we get a 429, that's the rate limiter working — expected under load
    if (is429) {
      check(res, {
        'detect: rate limit response is valid': (r) => r.body && r.body.length > 0,
      });
    }

    if (isOk) {
      check(res, {
        'detect: has valid JSON': (r) => {
          try { JSON.parse(r.body); return true; } catch { return false; }
        },
        'detect: has total_detections': (r) => {
          try { return typeof JSON.parse(r.body).total_detections === 'number'; } catch { return false; }
        },
      });
    }
  } else {
    const res = http.get(`${BASE}/stats`, { timeout: '30s', tags: { endpoint: 'stats' } });
    statsLatency.add(res.timings.duration);

    const isOk = res.status === 200;
    const isConnectionRefused = res.status === 0 && res.error.includes('connection refused');

    errorRate.add(!isOk);
    crashDetected.add(isConnectionRefused);

    check(res, {
      'stats: status is 200 or 429': (r) => r.status === 200 || r.status === 429,
      'stats: not crashed': (r) => !isConnectionRefused,
    });
  }

  sleep(Math.random() * 0.05);
}

export function handleSummary(data) {
  const total = data.metrics.http_reqs?.count || 0;
  const durationSecs = (data.state.testRunDurationMs || 1) / 1000;
  const rps = total / durationSecs;
  const failRate = (data.metrics.http_req_failed?.rate || 0) * 100;
  const crashRate = (data.metrics.crash?.rate || 0) * 100;

  // Determine per-scenario latency breakdown
  const scenarios = {};
  for (const [name, scenario] of Object.entries(data.scenarios || {})) {
    if (scenario.metrics) {
      const dur = scenario.metrics.http_req_duration;
      scenarios[name] = {
        requests: scenario.metrics.http_reqs?.count || 0,
        p50: dur ? dur.values?.['p(50)']?.toFixed(2) + 'ms' : 'N/A',
        p95: dur ? dur.values?.['p(95)']?.toFixed(2) + 'ms' : 'N/A',
        p99: dur ? dur.values?.['p(99)']?.toFixed(2) + 'ms' : 'N/A',
      };
    }
  }

  const summary = {
    break_test: {
      version: 'v0.3.0',
      product: 'AegisGate Rampart',
      timestamp: new Date().toISOString(),
      total_requests: total,
      duration_sec: durationSecs.toFixed(1),
      avg_rps: rps.toFixed(0),
      overall_latency: {
        avg: data.metrics.http_req_duration?.avg?.toFixed(2) + 'ms',
        p50: data.metrics.http_req_duration?.values?.['p(50)']?.toFixed(2) + 'ms',
        p90: data.metrics.http_req_duration?.values?.['p(90)']?.toFixed(2) + 'ms',
        p95: data.metrics.http_req_duration?.values?.['p(95)']?.toFixed(2) + 'ms',
        p99: data.metrics.http_req_duration?.values?.['p(99)']?.toFixed(2) + 'ms',
        max: data.metrics.http_req_duration?.values?.['max']?.toFixed(2) + 'ms',
      },
      detect_latency: {
        avg: data.metrics.detect_latency?.avg?.toFixed(2) + 'ms',
        p95: data.metrics.detect_latency?.values?.['p(95)']?.toFixed(2) + 'ms',
        p99: data.metrics.detect_latency?.values?.['p(99)']?.toFixed(2) + 'ms',
      },
      stats_latency: {
        avg: data.metrics.stats_latency?.avg?.toFixed(2) + 'ms',
        p95: data.metrics.stats_latency?.values?.['p(95)']?.toFixed(2) + 'ms',
      },
      error_rate: failRate.toFixed(2) + '%',
      crash_rate: crashRate.toFixed(4) + '%',
      degradation_rate: ((data.metrics.degraded?.rate || 0) * 100).toFixed(2) + '% of requests > 200ms',
      critical_rate: ((data.metrics.critical?.rate || 0) * 100).toFixed(2) + '% of requests > 1000ms or 5xx',
      peak_vus: 1000,
      per_scenario: scenarios,
      verdict: {
        crash_safe: crashRate === 0 ? '✅ PASS — Rampart stayed alive throughout' : '❌ FAIL — Connection refused detected, Rampart may have crashed',
        rate_limiter_working: failRate > 0 ? '✅ Rate limiter is enforcing limits' : '⚠️  No rate limiting observed (increase load or lower --rate-limit)',
        recovery_note: 'Observe latency returning to baseline in crush_20x ramp-down phase',
      },
    },
  };

  return {
    'results/break-test-results.json': JSON.stringify(summary, null, 2),
    stdout: JSON.stringify(summary, null, 2),
  };
}