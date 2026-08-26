// One arm x one run of the limiter-cost benchmark: constant arrival rate,
// with a warmup scenario whose samples are DISCARDED - only the
// `{scenario:measure}` sub-metrics are reported. The two scenarios run
// back-to-back so load never dips between warmup and measurement.
//
//   docker run --rm --network tollgate-bench \
//     -v $PWD/bench/k6:/scripts -v $PWD/bench/results:/results \
//     -e KEY=... -e ARM=redis -e RUN=1 grafana/k6:<tag> run /scripts/limiter_cost.js
import http from "k6/http";
import { check } from "k6";

const RATE = Number(__ENV.RATE || 1000);
const WARMUP_S = Number(__ENV.WARMUP_S || 10);
const MEASURE_S = Number(__ENV.MEASURE_S || 30);
const BASE = __ENV.BASE || "http://lb:8080";
const KEY = __ENV.KEY;
const ARM = __ENV.ARM || "unknown";
const RUN = Number(__ENV.RUN || 0);
const URL_PATH = __ENV.URL_PATH || "/echo/bench";

const scenarioDefaults = {
  executor: "constant-arrival-rate",
  rate: RATE,
  timeUnit: "1s",
  preAllocatedVUs: 300,
  maxVUs: 2000,
  gracefulStop: "5s",
};

export const options = {
  discardResponseBodies: true,
  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(95)", "p(99)"],
  scenarios: {
    warmup: { ...scenarioDefaults, duration: `${WARMUP_S}s` },
    measure: {
      ...scenarioDefaults,
      duration: `${MEASURE_S}s`,
      startTime: `${WARMUP_S}s`,
    },
  },
  // Empty threshold lists exist only to materialize the per-scenario
  // sub-metrics in the summary; nothing here aborts or fails the run.
  thresholds: {
    "http_req_duration{scenario:measure}": [],
    "http_req_failed{scenario:measure}": [],
    "http_reqs{scenario:measure}": [],
    "dropped_iterations{scenario:measure}": [],
  },
};

const params = { headers: { "X-API-Key": KEY } };

// Fail fast rather than measure garbage: one probe request must succeed
// before any load is generated.
export function setup() {
  if (!KEY) throw new Error("KEY env is required");
  const res = http.get(`${BASE}${URL_PATH}`, params);
  if (res.status !== 200) {
    throw new Error(`probe request got ${res.status}, expected 200 - is the stack seeded?`);
  }
}

export default function () {
  const res = http.get(`${BASE}${URL_PATH}`, params);
  check(res, { "status 200": (r) => r.status === 200 });
}

export function handleSummary(data) {
  const dur = data.metrics["http_req_duration{scenario:measure}"];
  const reqs = data.metrics["http_reqs{scenario:measure}"];
  const failed = data.metrics["http_req_failed{scenario:measure}"];
  const dropped = data.metrics["dropped_iterations{scenario:measure}"];
  if (!dur || !reqs) {
    throw new Error("measure-scenario sub-metrics missing from summary");
  }
  const row = {
    arm: ARM,
    run: RUN,
    offered_rps: RATE,
    warmup_s: WARMUP_S,
    measure_s: MEASURE_S,
    requests: reqs.values.count,
    achieved_rps: Number((reqs.values.count / MEASURE_S).toFixed(1)),
    p50_ms: Number(dur.values["p(50)"].toFixed(3)),
    p95_ms: Number(dur.values["p(95)"].toFixed(3)),
    p99_ms: Number(dur.values["p(99)"].toFixed(3)),
    avg_ms: Number(dur.values.avg.toFixed(3)),
    min_ms: Number(dur.values.min.toFixed(3)),
    max_ms: Number(dur.values.max.toFixed(3)),
    error_rate: Number(((failed && failed.values.rate) || 0).toFixed(5)),
    dropped_iterations: (dropped && dropped.values.count) || 0,
  };
  return {
    [`/results/cost-${ARM}-run${RUN}.json`]: JSON.stringify(row, null, 2) + "\n",
    stdout: JSON.stringify(row) + "\n",
  };
}
