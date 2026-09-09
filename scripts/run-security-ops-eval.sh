#!/usr/bin/env bash
#
# The security operations detection evaluation.
#
# Runs the scripted attack replay against the frozen design in
# secops/manifest.json, then runs it again from a build carrying a planted
# fault and REQUIRES that run to fail, then runs the normal build once more.
#
# Exits 0 only when all of the following hold:
#
#   - all 6 malicious scenarios detected
#   - 0 alerts on the matched benign replay
#   - tenant, trace, control and outcome present on every incident
#   - the normalized replay is identical across two runs
#   - the planted negative control was caught
#
# Everything runs locally, in one process, with no Redis, no Postgres, no
# network and no cost. The claims this evaluation makes and does not make are
# in secops/manifest.json and repeated at the top of the report it writes.

set -euo pipefail

cd "$(dirname "$0")/.."

MANIFEST="secops/manifest.json"
RESULTS="results"
SCRATCH=".agent-work/secops-negative-control"
NEGCTRL_LOG=".agent-work/negctrl-planted-fault.txt"
BIN=".agent-work/bin"

mkdir -p "$RESULTS"
mkdir -p "$SCRATCH"
mkdir -p "$BIN"

echo "==> building the replay harness"
go build -o "$BIN/tollgate-secops-replay" ./cmd/tollgate-secops-replay

echo "==> building the negative control (-tags secops_planted_fault)"
go build -tags secops_planted_fault -o "$BIN/tollgate-secops-replay-planted" ./cmd/tollgate-secops-replay

echo
echo "==> run 1 of 2: the evaluation"
"$BIN/tollgate-secops-replay" -manifest "$MANIFEST" -out "$RESULTS"

echo
echo "==> negative control: the same replay from a build with one correlation edge broken"
echo "    it must fail, or the linkage check cannot fail and no passing run means anything"
if "$BIN/tollgate-secops-replay-planted" -manifest "$MANIFEST" -out "$SCRATCH" > "$NEGCTRL_LOG" 2>&1; then
    echo "FAILED: the planted fault ran to a passing result. Output in $NEGCTRL_LOG"
    tail -n 30 "$NEGCTRL_LOG"
    exit 1
fi
echo "    the planted build exited non-zero, as required. Output in $NEGCTRL_LOG"

if ! grep -q "planted fault active in this build: true" "$NEGCTRL_LOG"; then
    echo "FAILED: the planted build does not report the fault as active; the build tag did not take"
    exit 1
fi

if ! grep -qE "^(incomplete-linkage|undetected): cert_binding_mismatch$" "$NEGCTRL_LOG"; then
    echo "FAILED: the planted build failed, but not on the incident the fault breaks."
    echo "        A run that fails for an unrelated reason is not a caught fault."
    grep -E "^(incomplete-linkage|undetected):" "$NEGCTRL_LOG" || echo "        (no scenario was reported incomplete or undetected)"
    exit 1
fi
echo "    it reported cert_binding_mismatch incomplete or undetected, which is the edge the fault breaks"

echo
echo "==> run 2 of 2: the evaluation again, from the restored normal build"
"$BIN/tollgate-secops-replay" -manifest "$MANIFEST" -out "$RESULTS"

echo
echo "==> detection delay"
grep -E "^Median detection delay" "$RESULTS/security-ops-report.md"

echo
echo "security operations evaluation passed: 6 of 6 malicious scenarios detected,"
echo "0 alerts on the matched benign replay, complete linkage, deterministic replay,"
echo "and the planted negative control was caught."
echo "Artifacts: $RESULTS/security-ops-timeline.jsonl, $RESULTS/security-ops-eval.json, $RESULTS/security-ops-report.md"
