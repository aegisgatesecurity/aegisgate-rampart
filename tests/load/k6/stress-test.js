// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Rampart — k6 Performance Test Suite
// =========================================================================
// Tests /detect and /stats endpoints under graduated load.
// Run: k6 run stress.js
// =========================================================================

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errorRate = new Rate('errors');
const detectLatency = new Trend('detect_latency', true);
const statsLatency = new Trend('stats_latency', true);

const BASE = __ENV.RAMPART_URL || 'http://127.0.0.1:8080';

const SAMPLES = {
  short: JSON.stringify({ text: 'My SSN is 123-45-6789' }),
  medium: JSON.stringify({ text: 'Hello, I need help with my account. My email is john@example.com and my phone is 555-123-4567. Also my credit card is 4111-1111-1111-1111. Can you help me reset my password? I also have an AWS key: AKIAIOSFODNN7EXAMPLE.' }),
  long: JSON.stringify({ text: 'A'.repeat(5000) + ' My SSN is 999-88-7777 and my API key is sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz.' }),
  nohit: JSON.stringify({ text: 'This is a perfectly safe message with no sensitive data whatsoever.' }),
};

export const options = {
  stages: [
    { duration: '20s', target: 5 },    // Warm up
    { duration: '20s', target: 20 },   // Light load
    { duration: '20s', target: 50 },   // Medium load
    { duration: '20s', target: 100 },  // Heavy load
    { duration: '10s', target: 0 },    // Cool down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<2000'],
    errors: ['rate<0.01'],
    detect_latency: ['p(95)<500', 'p(99)<1000'],
    stats_latency: ['p(95)<100'],
  },
};

export default function () {
  const keys = Object.keys(SAMPLES);
  const key = keys[Math.floor(Math.random() * keys.length)];
  const payload = SAMPLES[key];

  if (Math.random() < 0.85) {
    const res = http.post(`${BASE}/detect`, payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: '10s',
    });

    detectLatency.add(res.timings.duration);

    const ok = check(res, {
      'detect status 200': (r) => r.status === 200,
      'detect has JSON body': (r) => {
        try { JSON.parse(r.body); return true; } catch { return false; }
      },
      'detect has total_detections': (r) => {
        try { return typeof JSON.parse(r.body).total_detections === 'number'; } catch { return false; }
      },
    });

    errorRate.add(!ok);
  } else {
    const res = http.get(`${BASE}/stats`, { timeout: '5s' });
    statsLatency.add(res.timings.duration);

    const ok = check(res, {
      'stats status 200': (r) => r.status === 200,
      'stats has total_requests': (r) => {
        try { return typeof JSON.parse(r.body).total_requests === 'number'; } catch { return false; }
      },
    });

    errorRate.add(!ok);
  }

  sleep(0.1);
}