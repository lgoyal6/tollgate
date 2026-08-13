#!/usr/bin/env python3
"""Aggregate per-run k6 JSON summaries into arm distributions and the paired
same-round redis-minus-memory estimator. Also cross-checks against the gateway's own
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
    "none": "none    (limiter bypassed, floor)",
    "memory": "memory  (per-replica, no Redis in path)",
    "redis": "redis   (global, atomic Lua, default)",
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


def quartiles(values):
    """Tukey hinges: medians of the lower and upper halves."""
    ordered = sorted(values)
    if len(ordered) < 2:
        raise ValueError("at least two values are required for an IQR")
    midpoint = len(ordered) // 2
    lower = ordered[:midpoint]
    upper = ordered[-midpoint:]
    return statistics.median(lower), statistics.median(upper)


def distribution(values):
    values = list(values)
    q1, q3 = quartiles(values)
    return {
        "median": round(statistics.median(values), 4),
        "q1": round(q1, 4),
        "q3": round(q3, 4),
        "iqr": round(q3 - q1, 4),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "count": len(values),
    }


def fmt_distribution(values):
    dist = distribution(values)
    return (
        f"median {dist['median']:.4f} ms; "
        f"IQR {dist['q1']:.4f}..{dist['q3']:.4f} ms "
        f"(width {dist['iqr']:.4f} ms); "
        f"min..max {dist['min']:.4f}..{dist['max']:.4f} ms"
    )


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
        print("no cost-*.json results found; nothing to summarize", file=sys.stderr)
        sys.exit(1)

    arms = [a for a in ARM_ORDER if a in runs] + [a for a in runs if a not in ARM_ORDER]

    print("SECTION 2 - raw per-run numbers (k6, measure window only; warmup discarded)")
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

    print("SECTION 3 - per-arm p50 distributions across runs")
    for arm in arms:
        rs = runs[arm]
        print(f"  {ARM_LABEL.get(arm, arm)}   [{len(rs)} runs]")
        print(f"    p50 {fmt_distribution(r['p50_ms'] for r in rs)}")
    print()

    deltas = {}

    def delta_line(a, b, label):
        if a not in runs or b not in runs:
            return
        d = {
            k: round(med(runs[a], k) - med(runs[b], k), 4)
            for k in ("p50_ms", "p95_ms", "p99_ms")
        }
        deltas[f"{a}-{b}"] = d
        print(f"  {label:<44} p50 {d['p50_ms']:+8.4f} ms   p95 {d['p95_ms']:+8.4f} ms   p99 {d['p99_ms']:+8.4f} ms")

    print("  descriptive deltas of arm medians, not the headline estimator:")
    delta_line("redis", "memory", "redis - memory")
    delta_line("redis-sw", "memory", "redis-sw - memory (sliding-window variant)")
    delta_line("memory", "none", "memory - none (limiter middleware + math)")
    delta_line("redis", "none", "redis - none (global limiting vs nothing)")

    # Paired per-round p50 delta is the preselected headline estimator because
    # the interleaved design makes round the matching block.
    paired = None
    if "redis" in runs and "memory" in runs:
        by_run_r = {r["run"]: r for r in runs["redis"]}
        by_run_m = {r["run"]: r for r in runs["memory"]}
        common = sorted(set(by_run_r) & set(by_run_m))
        if common:
            pd = [round(by_run_r[n]["p50_ms"] - by_run_m[n]["p50_ms"], 3) for n in common]
            paired_dist = distribution(pd)
            paired = {
                "estimator": "median of paired same-round redis-minus-memory p50 deltas",
                "per_round_p50_ms": pd,
                **{f"{key}_p50_ms": value for key, value in paired_dist.items() if key != "count"},
                "pair_count": paired_dist["count"],
            }
            print()
            print("  HEADLINE: median of paired same-round redis-minus-memory p50 deltas")
            print(f"  per-round deltas: {pd}")
            print(f"  {fmt_distribution(pd)}; {len(pd)} pairs")
    print()

    means = checkhist_means(RESULTS)
    if means:
        print("SECTION 4 - in-gateway cross-check: mean limiter-check duration")
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
            a: {
                k: round(med(runs[a], k), 4)
                for k in ("p50_ms", "p95_ms", "p99_ms", "achieved_rps")
            }
            for a in arms
        },
        "spread": {
            a: {k: spread(runs[a], k) for k in ("p50_ms", "p95_ms", "p99_ms", "achieved_rps")}
            for a in arms
        },
        "p50_distribution_ms": {
            a: distribution(r["p50_ms"] for r in runs[a]) for a in arms
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
