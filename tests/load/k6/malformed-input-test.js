// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — Malformed Input Resilience Test
// =========================================================================
// Purpose: Ensure Rampart never crashes on malformed, invalid, or adversarial
//          input. This is CRITICAL for a local proxy — user traffic can be
//          anything, and we must handle it gracefully.
//
// Tests:
//   - Malformed JSON payloads
//   - Oversized payloads (10KB, 100KB, 1MB)
//   - Null bytes, binary data, control characters
//   - Missing/invalid Content-Type
//   - Empty bodies
//   - Unicode edge cases
//   - Extremely long strings
//   - Nested/recursive JSON
//   - HTTP method abuse
//   - Path traversal attempts
//   - SQL injection payloads (should be ignored, not crash)
//   - Very long headers
//
// CRITICAL: Every request must return a response. No crashes allowed.
//
// Run: k6 run --env RAMPART_URL=http://127.0.0.1:8080 malformed-input-test.js
// =========================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const crashDetected = new Rate('crash');
const serverError = new Rate('server_error');
const clientError = new Rate('client_error');
const successRate = new Rate('success');
const malformedLatency = new Trend('malformed_latency', true);
const rpsCounter = new Counter('rps');

const BASE = __ENV.RAMPART_URL || 'http://127.0.0.1:8080';

// Malformed / adversarial payloads
const malformedPayloads = [
  // Category 1: Invalid JSON
  { name: 'invalid_json_syntax', body: '{not json at all}',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'json_missing_brace', body: '{"text": "hello"',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'json_extra_brace', body: '{"text": "hello"}}',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'json_array_instead', body: '[{"text": "hello"}]',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'json_number_text', body: '{"text": 12345}',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'json_null_text', body: '{"text": null}',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'json_nested_object', body: '{"text": {"nested": "value"}}',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'json_empty_object', body: '{}',
    headers: { 'Content-Type': 'application/json' } },

  // Category 2: Wrong Content-Type
  { name: 'text_plain_content_type', body: '{"text": "SSN: 123-45-6789"}',
    headers: { 'Content-Type': 'text/plain' } },
  { name: 'form_urlencoded', body: 'text=My+SSN+is+123-45-6789',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  { name: 'no_content_type', body: '{"text": "SSN: 123-45-6789"}',
    headers: {} },
  { name: 'xml_content_type', body: '<?xml version="1.0"?><text>SSN 123-45-6789</text>',
    headers: { 'Content-Type': 'application/xml' } },

  // Category 3: Edge case sizes
  { name: 'empty_body', body: '',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'single_byte', body: 'x',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'large_10kb', body: JSON.stringify({ text: 'A'.repeat(10000) }),
    headers: { 'Content-Type': 'application/json' } },
  { name: 'large_100kb', body: JSON.stringify({ text: 'A'.repeat(100000) }),
    headers: { 'Content-Type': 'application/json' } },
  { name: 'huge_1mb', body: JSON.stringify({ text: 'A'.repeat(1000000) }),
    headers: { 'Content-Type': 'application/json' } },

  // Category 4: Binary and control characters
  { name: 'null_bytes', body: '{"text": "hello\x00world\x00SSN"}',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'control_chars', body: '{"text": "\x01\x02\x03\x04\x05"}',
    headers: { 'Content-Type': 'application/json' } },
  { name: 'unicode_bom', body: '\ufeff{"text": "hello"}',
    headers: { 'Content-Type': 'application/json' } },

  // Category 5: Unicode edge cases
  { name: 'emoji_overload', body: JSON.stringify({ text: '🔥'.repeat(1000) }),
    headers: { 'Content-Type': 'application/json' } },
  { name: 'right_to_left', body: JSON.stringify({ text: 'مرحبا العالمر مرحبا' }),
    headers: { 'Content-Type': 'application/json' } },
  { name: 'mixed_scripts', body: JSON.stringify({ text: 'Hello 你好 مرحبا Привет हैलो 🌍' }),
    headers: { 'Content-Type': 'application/json' } },
  { name: 'surrogate_pairs', body: JSON.stringify({ text: '\uD800\uDC00\uD801\uDCA1' }),
    headers: { 'Content-Type': 'application/json' } },

  // Category 6: Adversarial — should be detected but NOT crash
  { name: 'xss_payloads', body: JSON.stringify({ text: '<script>alert(1)</script><img src=x onerror=alert(1)><svg/onload=alert(1)>' }),
    headers: { 'Content-Type': 'application/json' } },
  { name: 'sql_injection', body: JSON.stringify({ text: "'; DROP TABLE users; -- OR 1=1 UNION SELECT * FROM credentials" }),
    headers: { 'Content-Type': 'application/json' } },
  { name: 'path_traversal', body: JSON.stringify({ text: '../../../etc/passwd ../../etc/shadow' }),
    headers: { 'Content-Type': 'application/json' } },
  { name: 'log_injection', body: JSON.stringify({ text: 'admin\nERROR: system compromised\n[CRITICAL]' }),
    headers: { 'Content-Type': 'application/json' } },

  // Category 7: Deeply nested JSON
  { name: 'deeply_nested_json', body: '{"text": "' + 'a'.repeat(100) + '", ' + '"extra": "' + 'b'.repeat(10000) + '"}',
    headers: { 'Content-Type': 'application/json' } },

  // Category 8: Valid PII (should be detected, not crash)
  { name: 'valid_ssn', body: JSON.stringify({ text: 'My SSN is 123-45-6789' }),
    headers: { 'Content-Type': 'application/json' } },
  { name: 'valid_credit_card', body: JSON.stringify({ text: 'CC: 4532-1234-5678-9010' }),
    headers: { 'Content-Type': 'application/json' } },
  { name: 'valid_api_key', body: JSON.stringify({ text: 'API key: AKIAIOSFODNN7EXAMPLE' }),
    headers: { 'Content-Type': 'application/json' } },
];

export const options = {
  scenarios: {
    // Phase 1: Sequential malformed input at moderate load
    sequential_malformed: {
      executor: 'constant-vus',
      vus: 50,
      duration: '60s',
      exec: 'sendMalformed',
    },
    // Phase 2: Burst malformed input — can Rampart handle sudden flood of bad data?
    burst_malformed: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 200 },
        { duration: '30s', target: 200 },
        { duration: '10s', target: 0 },
      ],
      exec: 'sendMalformed',
      startTime: '65s',
    },
    // Phase 3: High concurrency — many VUs sending different malformed data simultaneously
    concurrent_abuse: {
      executor: 'constant-vus',
      vus: 500,
      duration: '30s',
      exec: 'sendMalformed',
      startTime: '120s',
    },
    // Phase 4: Recovery — after abuse, does Rampart still work?
    recovery_after_abuse: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30s',
      exec: 'sendValid',
      startTime: '155s',
    },
    // Phase 5: HTTP method abuse and path traversal
    method_abuse: {
      executor: 'constant-vus',
      vus: 50,
      duration: '30s',
      exec: 'sendMethodAbuse',
      startTime: '190s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.80'],     // Allow many failures (malformed input), just no crashes
    http_req_duration: ['p(99)<30000'],  // 30s max
  },
};

export function sendMalformed() {
  const payload = malformedPayloads[Math.floor(Math.random() * malformedPayloads.length)];

  const res = http.post(`${BASE}/detect`, payload.body, {
    headers: payload.headers,
    timeout: '30s',
    tags: { test: 'malformed', payload_type: payload.name },
  });

  malformedLatency.add(res.timings.duration);
  rpsCounter.add(1);

  const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');
  const is5xx = res.status >= 500;
  const is4xx = res.status >= 400 && res.status < 500;

  crashDetected.add(isConnectionRefused);
  serverError.add(is5xx);
  clientError.add(is4xx);
  successRate.add(res.status === 200 || res.status === 429);

  check(res, {
    'response received (no crash)': (r) => r.status > 0 || !isConnectionRefused,
    'not a server error (5xx)': (r) => r.status < 500 || r.status === 0,
    [`malformed ${payload.name} handled`]: (r) => {
      // Any response is acceptable except crash
      // 400 (bad request) is expected for malformed input
      // 200 means it processed it somehow
      // 429 means rate limiter is working
      return r.status > 0;
    },
  });

  sleep(Math.random() * 0.05);
}

export function sendValid() {
  // Recovery test: send valid requests and verify Rampart still works
  const res = http.post(`${BASE}/detect`, JSON.stringify({ text: 'My SSN is 123-45-6789' }), {
    headers: { 'Content-Type': 'application/json' },
    timeout: '10s',
    tags: { test: 'recovery' },
  });

  rpsCounter.add(1);

  const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');
  crashDetected.add(isConnectionRefused);

  check(res, {
    'recovery: Rampart responds': (r) => r.status > 0,
    'recovery: not crashed': (r) => !isConnectionRefused,
    'recovery: returns 200 or 429': (r) => r.status === 200 || r.status === 429,
    'recovery: valid response': (r) => {
      if (r.status !== 200) return true; // 429 is OK
      try {
        const body = JSON.parse(r.body);
        return typeof body.total_detections === 'number';
      } catch { return false; }
    },
  });

  sleep(0.1);
}

export function sendMethodAbuse() {
  // HTTP method abuse — wrong methods, wrong paths
  const abuseTargets = [
    { method: 'GET', path: '/detect' },
    { method: 'PUT', path: '/detect' },
    { method: 'DELETE', path: '/detect' },
    { method: 'PATCH', path: '/detect' },
    { method: 'OPTIONS', path: '/detect' },
    { method: 'POST', path: '/detect/../../etc/passwd' },
    { method: 'POST', path: '/detect%00' },
    { method: 'POST', path: '/DETECT' },
    { method: 'POST', path: '/detect?foo=bar' },
    { method: 'GET', path: '/stats' },
    { method: 'POST', path: '/stats' },
    { method: 'GET', path: '/nonexistent' },
    { method: 'GET', path: '/' },
  ];

  const target = abuseTargets[Math.floor(Math.random() * abuseTargets.length)];

  const res = http.request(target.method, `${BASE}${target.path}`, '{"text":"test"}', {
    headers: { 'Content-Type': 'application/json' },
    timeout: '10s',
    tags: { test: 'method_abuse', method: target.method, path: target.path },
  });

  rpsCounter.add(1);

  const isConnectionRefused = res.status === 0 && (res.error || '').includes('connection refused');
  crashDetected.add(isConnectionRefused);

  check(res, {
    'method abuse: response received': (r) => r.status > 0 || !isConnectionRefused,
    'method abuse: no crash': (r) => !isConnectionRefused,
  });

  sleep(Math.random() * 0.05);
}

export function handleSummary(data) {
  const total = data.metrics.http_reqs?.count || 0;
  const dur = (data.state.testRunDurationMs || 1) / 1000;
  const crashPct = (data.metrics.crash?.rate || 0) * 100;
  const serverErrorPct = (data.metrics.server_error?.rate || 0) * 100;
  const successPct = (data.metrics.success?.rate || 0) * 100;

  const summary = {
    malformed_input_test: {
      version: 'v0.3.0',
      product: 'AegisGate Rampart',
      timestamp: new Date().toISOString(),
      total_requests: total,
      duration_sec: dur.toFixed(1),
      avg_rps: (total / dur).toFixed(0),
      crash_rate: crashPct.toFixed(4) + '%',
      server_error_rate: serverErrorPct.toFixed(2) + '%',
      success_rate: successPct.toFixed(2) + '%',
      latency: {
        avg: data.metrics.malformed_latency?.avg?.toFixed(2) + 'ms',
        p95: data.metrics.malformed_latency?.values?.['p(95)']?.toFixed(2) + 'ms',
        p99: data.metrics.malformed_latency?.values?.['p(99)']?.toFixed(2) + 'ms',
      },
      verdict: {
        crash_safe: crashPct === 0 ? '✅ PASS — Rampart never crashed on malformed input' : '❌ FAIL — Rampart crashed on malformed input',
        no_5xx: serverErrorPct < 5 ? '✅ PASS — Less than 5% server errors' : '⚠️  High server error rate on malformed input',
        graceful_degradation: successPct > 50 ? '✅ PASS — Rampart handled >50% of requests gracefully' : '⚠️  Many requests not handled gracefully',
      },
    },
  };

  return {
    'results/malformed-input-test-results.json': JSON.stringify(summary, null, 2),
    stdout: JSON.stringify(summary, null, 2),
  };
}