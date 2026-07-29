#!/usr/bin/env python3
"""Turn the k6 CSV from the Redis-outage run into a per-second timeline and
the outage findings: fail-open vs fail-closed (as observed, not as claimed),
error rate and p99 during the outage, and time to recover correct limiting
after Redis returns.

Usage:
  outage_timeline.py <k6.csv> <t0> <t_kill> <t_startcmd> <t_pong> <out.json>

Timestamps are unix epoch seconds (float ok; k6 CSV rows are 1s resolution,
so recovery time is reported at that resolution).
"""

import csv
import json
import statistics
import sys


def pctl(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    idx = min(len(s) - 1, max(0, round(q * (len(s) - 1))))
    return s[idx]


def norm_ts(ts):
    ts = float(ts)
    if ts > 1e17:  # ns
        return ts / 1e9
    if ts > 1e14:  # us
        return ts / 1e6
    if ts > 1e11:  # ms
        return ts / 1e3
    return ts


def main():
    path, t0, t_kill, t_startcmd, t_pong, out_path = sys.argv[1:7]
    t0, t_kill, t_startcmd, t_pong = map(float, (t0, t_kill, t_startcmd, t_pong))

    bins = {}  # int second -> {"s200": n, "s429": n, "s503": n, "s5xx": n, "err": n, "lat": [...]}
    first_ts = None
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["metric_name"] != "http_req_duration":
                continue
            ts = norm_ts(row["timestamp"])
            if first_ts is None or ts < first_ts:
                first_ts = ts
            sec = int(ts)
            b = bins.setdefault(sec, {"s200": 0, "s429": 0, "s503": 0, "s5xx": 0, "err": 0, "lat": []})
            status = row.get("status", "")
            if status == "200":
                b["s200"] += 1
            elif status == "429":
                b["s429"] += 1
            elif status == "503":
                b["s503"] += 1
            elif status.startswith("5"):
                b["s5xx"] += 1
            else:
                b["err"] += 1  # status 0 / transport errors
            b["lat"].append(float(row["metric_value"]))

    if not bins:
        print("no http_req_duration rows found in CSV — outage run produced no data", file=sys.stderr)
        sys.exit(1)

    secs = sorted(bins)

    def phase_stats(lo, hi):  # [lo, hi) absolute epoch seconds
        rows = [bins[s] for s in secs if lo <= s < hi]
        if not rows:
            return None
        lat = [v for r in rows for v in r["lat"]]
        total = len(lat)
        return {
            "seconds": len(rows),
            "requests": total,
            "s200": sum(r["s200"] for r in rows),
            "s429": sum(r["s429"] for r in rows),
            "s503": sum(r["s503"] for r in rows),
            "s5xx": sum(r["s5xx"] for r in rows),
            "transport_errors": sum(r["err"] for r in rows),
            "p50_ms": round(statistics.median(lat), 3),
            "p99_ms": round(pctl(lat, 0.99), 3),
            "max_ms": round(max(lat), 3),
        }

    end = secs[-1] + 1
    # Skip the first 5s of the healthy phase (connection warmup).
    phases = {
        "healthy (pre-kill, first 5s skipped)": phase_stats(secs[0] + 5, t_kill),
        "outage (kill -> redis PONG)": phase_stats(t_kill, t_pong),
        "recovered (after redis PONG)": phase_stats(t_pong, end),
    }

    # Recovery: first second at/after PONG in which a 429 was served again.
    recovered_at = None
    for s in secs:
        if s >= int(t_pong) and bins[s]["s429"] > 0:
            recovered_at = s
            break

    out = {
        "t0": t0, "t_kill": t_kill, "t_startcmd": t_startcmd, "t_pong": t_pong,
        "phases": phases,
        "recovered_at": recovered_at,
        "recovery_seconds_after_pong": None if recovered_at is None else recovered_at - int(t_pong),
        "timeline": [],
    }

    print("SECTION 5 — Redis-unavailable behaviour (one run, timestamps epoch-second resolution)")
    print(f"  offered load: metered tenant (sliding window, limit 300/s), constant arrival")
    print(f"  t_kill      = {t_kill:.1f} (docker compose kill redis)")
    print(f"  t_startcmd  = {t_startcmd:.1f} (docker compose start redis, +{t_startcmd - t_kill:.1f}s)")
    print(f"  t_pong      = {t_pong:.1f} (redis answers PING again, +{t_pong - t_startcmd:.1f}s after start)")
    print()
    for name, st in phases.items():
        if st is None:
            print(f"  {name}: NO DATA")
            continue
        tot = st["requests"]
        print(f"  {name}: {tot} reqs over {st['seconds']}s")
        print(f"    200 {st['s200']} ({st['s200']/tot*100:.1f}%)   429 {st['s429']} ({st['s429']/tot*100:.1f}%)   "
              f"503 {st['s503']}   other-5xx {st['s5xx']}   transport-errors {st['transport_errors']}")
        print(f"    p50 {st['p50_ms']} ms   p99 {st['p99_ms']} ms   max {st['max_ms']} ms")
    print()

    o = phases["outage (kill -> redis PONG)"]
    if o:
        verdict = []
        if o["s503"] == 0 and o["s200"] > 0 and o["s429"] == 0:
            verdict.append("FAIL-OPEN observed: during the outage every request was admitted (200),")
            verdict.append("zero 429s and zero 503s — the limit silently ceased to exist.")
        elif o["s503"] > 0 and o["s200"] == 0:
            verdict.append("FAIL-CLOSED observed: requests were rejected 503 during the outage.")
        else:
            verdict.append("MIXED behaviour during outage — inspect the timeline below.")
        for line in verdict:
            print(f"  {line}")
        out["verdict"] = " ".join(verdict)
    print()

    if recovered_at is not None:
        print(f"  recovery: first 429 after redis PONG at second {recovered_at} "
              f"(= {recovered_at - int(t_pong)}s after PONG, 1s bin resolution)")
        nxt = [s for s in secs if s >= recovered_at][:5]
        print(f"  first seconds after recovery (admitted-per-second vs limit 300):")
        for s in nxt:
            b = bins[s]
            print(f"    t+{s - int(t_kill)}s: 200={b['s200']} 429={b['s429']} err={b['err']}")
    else:
        print("  recovery: NO 429 seen after redis PONG — limiting did NOT resume in-window!")
    print()

    print("  per-second timeline (offset from kill; negative = before kill):")
    print(f"  {'t-kill':>7} {'total':>6} {'200':>5} {'429':>5} {'503':>5} {'5xx':>5} {'err':>5} {'p50ms':>8} {'p99ms':>9}")
    for s in secs:
        b = bins[s]
        tot = len(b["lat"])
        mark = ""
        if s == int(t_kill):
            mark = "  <- kill"
        elif s == int(t_pong):
            mark = "  <- redis back"
        row = {
            "sec_offset_from_kill": s - int(t_kill),
            "total": tot, "s200": b["s200"], "s429": b["s429"], "s503": b["s503"],
            "s5xx": b["s5xx"], "transport_errors": b["err"],
            "p50_ms": round(statistics.median(b["lat"]), 2),
            "p99_ms": round(pctl(b["lat"], 0.99), 2),
        }
        out["timeline"].append(row)
        print(f"  {s - int(t_kill):>7} {tot:>6} {b['s200']:>5} {b['s429']:>5} {b['s503']:>5} "
              f"{b['s5xx']:>5} {b['err']:>5} {row['p50_ms']:>8.2f} {row['p99_ms']:>9.2f}{mark}")

    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)


if __name__ == "__main__":
    main()
