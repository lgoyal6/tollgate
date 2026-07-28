// Tenant fairness / noisy-neighbour test.
//
// `noisy` offers 4x its own quota; `quiet` stays at 50% of its quota. If
// per-tenant isolation works, quiet sees ~zero 429s and stable latency while
// noisy eats rejections. Both tenants share the same upstream pool, so this
// also shows 429s being served before upstream capacity is consumed.
//
//   k6 run -e NOISY_KEY=... -e QUIET_KEY=... loadtest/fairness.js
import http from "k6/http";
import { Counter, Trend } from "k6/metrics";

const BASE = __ENV.BASE || "http://127.0.0.1:30080";
const LIMIT = Number(__ENV.LIMIT || 200); // both tenants' rl_limit per second
const DURATION = __ENV.DURATION || "30s";

const quiet429 = new Counter("quiet_429");
const quiet200 = new Counter("quiet_200");
const noisy429 = new Counter("noisy_429");
const noisy200 = new Counter("noisy_200");
const quietLatency = new Trend("quiet_latency", true);

export const options = {
  discardResponseBodies: true,
  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(90)", "p(95)", "p(99)"],
  scenarios: {
    noisy: {
      executor: "constant-arrival-rate",
      exec: "noisy",
      rate: LIMIT * 4,
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: LIMIT,
      maxVUs: LIMIT * 4,
    },
    quiet: {
      executor: "constant-arrival-rate",
      exec: "quiet",
      rate: Math.floor(LIMIT / 2),
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: 50,
      maxVUs: LIMIT,
    },
  },
  thresholds: {
    quiet_429: [{ threshold: "count<5", abortOnFail: false }],
  },
};

export function noisy() {
  const res = http.get(`${BASE}/echo/n`, { headers: { "X-API-Key": __ENV.NOISY_KEY } });
  if (res.status === 429) noisy429.add(1);
  else if (res.status === 200) noisy200.add(1);
}

export function quiet() {
  const res = http.get(`${BASE}/echo/q`, { headers: { "X-API-Key": __ENV.QUIET_KEY } });
  quietLatency.add(res.timings.duration);
  if (res.status === 429) quiet429.add(1);
  else if (res.status === 200) quiet200.add(1);
}

export function handleSummary(data) {
  const m = data.metrics;
  const count = (name) => (m[name] ? m[name].values.count : 0);
  const q200 = count("quiet_200");
  const q429 = count("quiet_429");
  const row = {
    duration: DURATION,
    tenant_limit_per_s: LIMIT,
    noisy_offered_rps: LIMIT * 4,
    quiet_offered_rps: Math.floor(LIMIT / 2),
    noisy_200: count("noisy_200"),
    noisy_429: count("noisy_429"),
    quiet_200: q200,
    quiet_429: q429,
    quiet_429_rate: Number((q429 / Math.max(1, q200 + q429)).toFixed(5)),
    quiet_p99_ms: Number(m.quiet_latency.values["p(99)"].toFixed(2)),
    quiet_starved: q429 > (q200 + q429) * 0.01,
  };
  return {
    "loadtest/results/fairness.json": JSON.stringify(row, null, 2),
    stdout: JSON.stringify(row, null, 2) + "\n",
  };
}
