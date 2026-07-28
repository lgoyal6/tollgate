// Distributed rate limit correctness test.
//
// The `metered` tenant allows exactly LIMIT requests per 1s sliding window.
// This script offers ~4x that rate for DURATION seconds, spread across all
// gateway replicas, then compares admitted (200) requests against the
// mathematical ceiling LIMIT * (windows + 1).
//
// Run once against RATE_LIMITER=redis (admitted ≈ ceiling) and once against
// RATE_LIMITER=memory (admitted ≈ replicas × ceiling — the naive failure).
//
//   k6 run -e LIMIT=300 -e DURATION=30 -e KEY=$K6_KEY_METERED \
//          -e LABEL=redis loadtest/correctness.js
import http from "k6/http";
import { Counter } from "k6/metrics";

const LIMIT = Number(__ENV.LIMIT || 300); // must match the tenant's rl_limit
const DURATION = Number(__ENV.DURATION || 30); // seconds
const BASE = __ENV.BASE || "http://127.0.0.1:30080";
const KEY = __ENV.KEY;
const LABEL = __ENV.LABEL || "unlabelled";

const admitted = new Counter("admitted_2xx");
const limited = new Counter("limited_429");
const other = new Counter("other_status");

export const options = {
  discardResponseBodies: true,
  scenarios: {
    blast: {
      executor: "constant-arrival-rate",
      rate: LIMIT * 4,
      timeUnit: "1s",
      duration: `${DURATION}s`,
      preAllocatedVUs: LIMIT,
      maxVUs: LIMIT * 4,
    },
  },
};

const params = { headers: { "X-API-Key": KEY } };

export default function () {
  const res = http.get(`${BASE}/echo/meter`, params);
  if (res.status === 200) admitted.add(1);
  else if (res.status === 429) limited.add(1);
  else other.add(1);
}

export function handleSummary(data) {
  const m = data.metrics;
  const got = m.admitted_2xx ? m.admitted_2xx.values.count : 0;
  const rejected = m.limited_429 ? m.limited_429.values.count : 0;
  const errs = m.other_status ? m.other_status.values.count : 0;
  // Sliding window of 1s over DURATION seconds: at most LIMIT per window,
  // +1 window for boundary overlap.
  const ceiling = LIMIT * (DURATION + 1);
  const row = {
    limiter: LABEL,
    tenant_limit_per_s: LIMIT,
    offered_rps: LIMIT * 4,
    duration_s: DURATION,
    admitted_200: got,
    rejected_429: rejected,
    other: errs,
    ceiling: ceiling,
    admitted_over_ceiling_pct: Number((((got - ceiling) / ceiling) * 100).toFixed(1)),
    globally_correct: got <= ceiling * 1.02, // 2% measurement slack
  };
  return {
    [`loadtest/results/correctness-${LABEL}.json`]: JSON.stringify(row, null, 2),
    stdout: JSON.stringify(row, null, 2) + "\n",
  };
}
