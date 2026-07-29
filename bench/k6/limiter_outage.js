// Redis-outage experiment: constant arrival rate against a tenant whose
// limit is BELOW the offered rate (so 429s are the steady-state signal that
// limiting works). bench/run.sh kills Redis mid-run and restarts it; the
// per-second timeline comes from `--out csv`, post-processed by
// bench/outage_timeline.py. This script only generates load and records an
// aggregate summary.
import http from "k6/http";

const RATE = Number(__ENV.RATE || 600);
const DURATION_S = Number(__ENV.DURATION_S || 110);
const BASE = __ENV.BASE || "http://lb:8080";
const KEY = __ENV.KEY;
const URL_PATH = __ENV.URL_PATH || "/echo/outage";

export const options = {
  discardResponseBodies: true,
  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(95)", "p(99)"],
  scenarios: {
    outage: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: `${DURATION_S}s`,
      // Sized so the arrival rate holds even if every request suddenly
      // takes seconds (Redis timeouts): rate * worst-case latency.
      preAllocatedVUs: 500,
      maxVUs: 3000,
      gracefulStop: "10s",
    },
  },
};

const params = { headers: { "X-API-Key": KEY } };

export function setup() {
  if (!KEY) throw new Error("KEY env is required");
  const res = http.get(`${BASE}${URL_PATH}`, params);
  if (res.status !== 200 && res.status !== 429) {
    throw new Error(`probe request got ${res.status}, expected 200/429`);
  }
}

export default function () {
  http.get(`${BASE}${URL_PATH}`, params);
}

export function handleSummary(data) {
  const m = data.metrics;
  const row = {
    offered_rps: RATE,
    duration_s: DURATION_S,
    requests: m.http_reqs.values.count,
    p50_ms: Number(m.http_req_duration.values["p(50)"].toFixed(3)),
    p99_ms: Number(m.http_req_duration.values["p(99)"].toFixed(3)),
    max_ms: Number(m.http_req_duration.values.max.toFixed(3)),
    dropped_iterations: m.dropped_iterations ? m.dropped_iterations.values.count : 0,
  };
  return {
    "/results/outage-summary.json": JSON.stringify(row, null, 2) + "\n",
    stdout: JSON.stringify(row) + "\n",
  };
}
