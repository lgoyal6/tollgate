#!/usr/bin/env python3
"""Aggregate the per-run k6 JSON summaries (bench/results/cost-*.json) into
medians, run-to-run spread, and the arm-to-arm deltas the benchmark exists
for. Also cross-checks against the gateway's own
tollgate_ratelimit_check_duration_seconds histogram scrapes when present.

Prints the report sections as text (stdout) and writes summary.json.
Never fabricates: runs failing validity checks are printed and flagged, and
excluded from medians only with an explicit note.
"""

import glob
import json
import os
import re
import statistics
import sys

RESULTS = sys.argv[1] if len(sys.argv) > 1 else "bench/results"
ARM_ORDER = ["none", "memory", "redis", "redis-sw"]
ARM_LABEL = {
    "none": "none    (limiter bypassed — floor)",
    "memory": "memory  (per-replica, no Redis in path)",
    "redis": "redis   (global, atomic Lua — default)",
    "redis-sw": "redis-sw (global, sliding-window script)",
}


def load_runs():
    runs = {}
    for path in sorted(glob.glob(os.path.join(RESULTS, "cost-*-run*.json"))):
        with open(path) as f:
            row = json.load(f)
        runs.setdefault(row["arm"], []).append(row)
    for arm in runs:
        runs[arm].sort(key=lambda r: r["run"])
    return runs


def valid(row):
    problems = []
    if row["error_rate"] > 0.01:
        problems.append(f"error_rate={row['error_rate']}")
    if row["achieved_rps"] < 0.97 * row["offered_rps"]:
        problems.append(f"achieved {row['achieved_rps']} < 97% of offered {row['offered_rps']}")
    if row["dropped_iterations"] > 0.01 * row["offered_rps"] * row["measure_s"]:
        problems.append(f"dropped_iterations={row['dropped_iterations']}")
    return problems


def med(rows, key):
    return statistics.median(r[key] for r in rows)


def spread(rows, key):
    vals = [r[key] for r in rows]
    return min(vals), max(vals)


def fmt_med_spread(rows, key, unit="ms"):
    lo, hi = spread(rows, key)
    return f"{med(rows, key):8.3f} ({lo:.3f}..{hi:.3f})"


def checkhist_means(results_dir):
    """Mean limiter-check duration per (arm, run) from /metrics scrapes.

    Scrapes are cumulative per gateway deployment. Within a round, the
    redis-arm deployment serves the 'redis' run first, then 'redis-sw', so
    the sw mean is computed from the delta between the two scrapes.
    """
    pat = re.compile(
        r"^(gateway-\d+) tollgate_ratelimit_check_duration_seconds_(sum|count) (\S+)$"
    )
    scrapes = {}  # (arm, run) -> {gateway: {"sum": x, "count": y}}
    for path in glob.glob(os.path.join(results_dir, "checkhist-*-run*.prom")):
        m = re.match(r"checkhist-(.+)-run(\d+)\.prom$", os.path.basename(path))
        if not m:
            continue
        arm, run = m.group(1), int(m.group(2))
        per_gw = {}
        with open(path) as f:
            for line in f:
                pm = pat.match(line.strip())
                if pm:
                    gw, kind, val = pm.group(1), pm.group(2), float(pm.group(3))
                    per_gw.setdefault(gw, {})[kind] = val
        scrapes[(arm, run)] = per_gw

    means = {}  # (arm, run) -> mean seconds
    for (arm, run), per_gw in scrapes.items():
        tot_sum = sum(g.get("sum", 0.0) for g in per_gw.values())
        tot_count = sum(g.get("count", 0.0) for g in per_gw.values())
        if arm == "redis-sw":
            base = scrapes.get(("redis", run), {})
            tot_sum -= sum(g.get("sum", 0.0) for g in base.values())
            tot_count -= sum(g.get("count", 0.0) for g in base.values())
        if tot_count > 0:
            means[(arm, run)] = tot_sum / tot_count
    return means


def main():
    runs = load_runs()
    if not runs:
        print("no cost-*.json results found — nothing to summarize", file=sys.stderr)
        sys.exit(1)

    arms = [a for a in ARM_ORDER if a in runs] + [a for a in runs if a not in ARM_ORDER]

    print("SECTION 2 — raw per-run numbers (k6, measure window only; warmup discarded)")
    print(f"{'arm':<9} {'run':>3} {'p50_ms':>8} {'p95_ms':>8} {'p99_ms':>8} "
          f"{'avg_ms':>8} {'max_ms':>9} {'rps':>8} {'err':>8} {'dropped':>7}")
    invalid_runs = []
    for arm in arms:
        for r in runs[arm]:
            problems = valid(r)
            flag = "  <-- INVALID: " + "; ".join(problems) if problems else ""
            if problems:
                invalid_runs.append((arm, r["run"], problems))
            print(f"{arm:<9} {r['run']:>3} {r['p50_ms']:>8.3f} {r['p95_ms']:>8.3f} "
                  f"{r['p99_ms']:>8.3f} {r['avg_ms']:>8.3f} {r['max_ms']:>9.3f} "
                  f"{r['achieved_rps']:>8.1f} {r['error_rate']:>8.5f} "
                  f"{r['dropped_iterations']:>7}{flag}")
    print()
    if invalid_runs:
        print("!! Some runs failed validity checks (saturation or errors); they are")
        print("!! shown above but EXCLUDED from the medians below:")
        for arm, run, problems in invalid_runs:
            print(f"!!   {arm} run {run}: {'; '.join(problems)}")
        print()
        runs = {a: [r for r in rs if not valid(r)] for a, rs in runs.items()}
        runs = {a: rs for a, rs in runs.items() if rs}
        arms = [a for a in arms if a in runs]

    print("SECTION 3 — medians across runs (spread = min..max across runs)")
    for arm in arms:
        rs = runs[arm]
        print(f"  {ARM_LABEL.get(arm, arm)}   [{len(rs)} runs]")
        print(f"    p50 {fmt_med_spread(rs, 'p50_ms')} ms   "
              f"p95 {fmt_med_spread(rs, 'p95_ms')} ms")
        print(f"    p99 {fmt_med_spread(rs, 'p99_ms')} ms   "
              f"throughput {med(rs, 'achieved_rps'):8.1f} ({spread(rs, 'achieved_rps')[0]:.1f}..{spread(rs, 'achieved_rps')[1]:.1f}) rps")
    print()

    deltas = {}

    def delta_line(a, b, label):
        if a not in runs or b not in runs:
            return
        d = {k: med(runs[a], k) - med(runs[b], k) for k in ("p50_ms", "p95_ms", "p99_ms")}
        deltas[f"{a}-{b}"] = d
        print(f"  {label:<44} p50 {d['p50_ms']:+7.3f} ms   p95 {d['p95_ms']:+7.3f} ms   p99 {d['p99_ms']:+7.3f} ms")

    print("  deltas of medians:")
    delta_line("redis", "memory", "redis - memory (THE cost of the global RTT)")
    delta_line("redis-sw", "memory", "redis-sw - memory (sliding-window variant)")
    delta_line("memory", "none", "memory - none (limiter middleware + math)")
    delta_line("redis", "none", "redis - none (global limiting vs nothing)")

    # Paired per-round p50 delta: both arms measured in the same round share
    # thermal/background conditions, so this is the tighter estimate.
    paired = None
    if "redis" in runs and "memory" in runs:
        by_run_r = {r["run"]: r for r in runs["redis"]}
        by_run_m = {r["run"]: r for r in runs["memory"]}
        common = sorted(set(by_run_r) & set(by_run_m))
        if common:
            pd = [round(by_run_r[n]["p50_ms"] - by_run_m[n]["p50_ms"], 3) for n in common]
            paired = {"per_round_p50_ms": pd, "median_p50_ms": statistics.median(pd)}
            print()
            print(f"  paired per-round p50 delta (redis - memory), same-round pairs: {pd}")
            print(f"  median paired p50 delta: {statistics.median(pd):+.3f} ms")
    print()

    means = checkhist_means(RESULTS)
    if means:
        print("SECTION 4 — in-gateway cross-check: mean limiter-check duration")
        print("  (tollgate_ratelimit_check_duration_seconds, sum/count across the 3")
        print("  replicas, scraped after each run; redis-sw is the within-deployment delta)")
        by_arm = {}
        for (arm, run), v in sorted(means.items()):
            by_arm.setdefault(arm, []).append(v * 1000)
        for arm in [a for a in ARM_ORDER if a in by_arm]:
            vals = by_arm[arm]
            print(f"    {arm:<9} mean check {statistics.median(vals):7.3f} ms "
                  f"(runs: {', '.join(f'{v:.3f}' for v in vals)})")
        print()

    out = {
        "runs": {a: runs[a] for a in arms},
        "medians": {
            a: {k: med(runs[a], k) for k in ("p50_ms", "p95_ms", "p99_ms", "achieved_rps")}
            for a in arms
        },
        "spread": {
            a: {k: spread(runs[a], k) for k in ("p50_ms", "p95_ms", "p99_ms", "achieved_rps")}
            for a in arms
        },
        "deltas_of_medians_ms": deltas,
        "paired_redis_minus_memory": paired,
        "invalid_runs": [{"arm": a, "run": n, "problems": p} for a, n, p in invalid_runs],
        "check_duration_mean_ms": {f"{a}-run{n}": v * 1000 for (a, n), v in means.items()},
    }
    with open(os.path.join(RESULTS, "summary.json"), "w") as f:
        json.dump(out, f, indent=2)


if __name__ == "__main__":
    main()
