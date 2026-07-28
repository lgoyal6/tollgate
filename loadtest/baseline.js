// Baseline load test: measures gateway latency and error rate at a constant
// arrival rate against the unlimited `loadtest` tenant, so what's measured is
// proxy overhead (auth + rate-limit check + forward), not 429s.
//
//   k6 run -e RATE=500 -e DURATION=60s -e KEY=$K6_KEY_LOADTEST \
//          -e BASE=http://127.0.0.1:30080 loadtest/baseline.js
import http from "k6/http";
import { check } from "k6";

const RATE = Number(__ENV.RATE || 500);
const DURATION = __ENV.DURATION || "60s";
const BASE = __ENV.BASE || "http://127.0.0.1:30080";
const KEY = __ENV.KEY;

export const options = {
  discardResponseBodies: true,
  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(90)", "p(95)", "p(99)"],
  scenarios: {
    baseline: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: Math.max(50, Math.ceil(RATE / 4)),
      maxVUs: Math.max(200, RATE),
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    dropped_iterations: ["count<" + Math.max(10, RATE * 0.01)],
  },
};

const params = { headers: { "X-API-Key": KEY } };

export default function () {
  const res = http.get(`${BASE}/echo/bench`, params);
  check(res, { "status 200": (r) => r.status === 200 });
}

export function handleSummary(data) {
  const m = data.metrics;
  const row = {
    target_rps: RATE,
    duration: DURATION,
    achieved_rps: Number((m.http_reqs.values.rate || 0).toFixed(1)),
    p50_ms: Number(m.http_req_duration.values["p(50)"].toFixed(2)),
    p95_ms: Number(m.http_req_duration.values["p(95)"].toFixed(2)),
    p99_ms: Number(m.http_req_duration.values["p(99)"].toFixed(2)),
    error_rate: Number((m.http_req_failed.values.rate || 0).toFixed(5)),
    requests: m.http_reqs.values.count,
    dropped: m.dropped_iterations ? m.dropped_iterations.values.count : 0,
  };
  return {
    [`loadtest/results/baseline-${RATE}.json`]: JSON.stringify(row, null, 2),
    stdout: JSON.stringify(row, null, 2) + "\n",
  };
}
