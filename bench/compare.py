#!/usr/bin/env python3
"""Compare two matched limiter-cost summaries without estimating values."""

import json
import os
import sys


def load_summary(directory):
    path = os.path.join(directory, "summary.json")
    with open(path) as f:
        return json.load(f)


def selected(summary):
    paired = summary["paired_redis_minus_memory"]
    return {
        "arms_p50_ms": summary["p50_distribution_ms"],
        "redis_minus_memory_p50_ms": paired,
    }


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: compare.py LOCAL_RESULTS EKS_RESULTS OUTPUT_JSON")

    local = selected(load_summary(sys.argv[1]))
    incluster = selected(load_summary(sys.argv[2]))
    local_delta = local["redis_minus_memory_p50_ms"]
    incluster_delta = incluster["redis_minus_memory_p50_ms"]

    intersection_low = max(local_delta["q1_p50_ms"], incluster_delta["q1_p50_ms"])
    intersection_high = min(local_delta["q3_p50_ms"], incluster_delta["q3_p50_ms"])
    overlaps = intersection_low <= intersection_high

    comparison = {
        "estimator": "median of paired same-round redis-minus-memory p50 deltas",
        "interval_definition": "Tukey-hinge Q1..Q3 of paired same-round deltas",
        "environments": {"local": local, "aws_eks": incluster},
        "intervals_overlap": overlaps,
        "intersection_q1_q3_ms": [intersection_low, intersection_high] if overlaps else None,
    }
    with open(sys.argv[3], "w") as f:
        json.dump(comparison, f, indent=2)
        f.write("\n")

    for name, result in comparison["environments"].items():
        print(name)
        for arm, dist in result["arms_p50_ms"].items():
            print(
                f"  {arm} p50: median {dist['median']:.4f} ms; "
                f"IQR {dist['q1']:.4f}..{dist['q3']:.4f} ms "
                f"(width {dist['iqr']:.4f} ms); "
                f"min..max {dist['min']:.4f}..{dist['max']:.4f} ms"
            )
        delta = result["redis_minus_memory_p50_ms"]
        print(
            f"  paired redis-minus-memory p50: median {delta['median_p50_ms']:.4f} ms; "
            f"IQR {delta['q1_p50_ms']:.4f}..{delta['q3_p50_ms']:.4f} ms "
            f"(width {delta['iqr_p50_ms']:.4f} ms); "
            f"min..max {delta['min_p50_ms']:.4f}..{delta['max_p50_ms']:.4f} ms"
        )
    if overlaps:
        print(
            "The local and AWS EKS paired-delta IQR intervals overlap: "
            f"intersection {intersection_low:.4f}..{intersection_high:.4f} ms."
        )
    else:
        print("The local and AWS EKS paired-delta IQR intervals do not overlap.")


if __name__ == "__main__":
    main()
