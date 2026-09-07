#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
rollout="$root/scripts/cloud-run-rollout.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
common=(--project example --dry-run --current-traffic rev-a=70,rev-b=30 \
  --current-tags stable=rev-a,preview=rev-b --observe-seconds 0)

"$rollout" --app tollgate --environment stage --image example/tollgate:test \
  "${common[@]}" >"$tmp/success"
grep -q 'gcloud run deploy tollgate-gateway-stage' "$tmp/success"
grep -q 'tollgate-gateway-stage-rollout-' "$tmp/success"
grep -Eq 'tollgate-gateway-stage-rollout-[0-9]+=10\\,rev-a=63\\,rev-b=27' "$tmp/success"
canary_line="$(grep -n 'probe-tagged-revision' "$tmp/success" | cut -d: -f1)"
shift_line="$(grep -n 'rev-a=63\\,rev-b=27' "$tmp/success" | cut -d: -f1)"
[ "$canary_line" -gt "$shift_line" ] || { echo "canary probe ran before traffic shift" >&2; exit 1; }
grep -q 'remove-tags' "$tmp/success"

set +e
"$rollout" --app argus --environment prod --image example/argus:test \
  "${common[@]}" --seed-failure >"$tmp/seed" 2>"$tmp/seed.err"
seed_status=$?
"$rollout" --app argus --environment prod --image example/argus:test \
  "${common[@]}" --dry-run-fail-at canary-update >"$tmp/fail" 2>"$tmp/fail.err"
fail_status=$?
"$rollout" --app argus --environment prod --image example/argus:test \
  "${common[@]}" --dry-run-interrupt-at observe >"$tmp/interrupt" 2>"$tmp/interrupt.err"
interrupt_status=$?
set -e

[ "$seed_status" -ne 0 ] || { echo "seeded failure returned success" >&2; exit 1; }
[ "$fail_status" -eq 97 ] || { echo "failed update returned $fail_status, want 97" >&2; exit 1; }
[ "$interrupt_status" -eq 130 ] || { echo "interrupt returned $interrupt_status, want 130" >&2; exit 1; }
for name in seed fail interrupt; do
  grep -q 'rev-a=70\\,rev-b=30' "$tmp/$name"
  grep -q 'stable=rev-a\\,preview=rev-b' "$tmp/$name"
done
grep -q 'simulating command failure at canary-update' "$tmp/fail.err"
grep -q 'simulating interrupt at observe' "$tmp/interrupt.err"

set +e
"$rollout" --app tollgate --environment stage --image example/tollgate:test \
  --project example --dry-run --current-traffic rev-a=100 \
  --dry-run-fail-at deploy >"$tmp/no-tags" 2>/dev/null
no_tags_status=$?
set -e
[ "$no_tags_status" -eq 97 ] || { echo "deploy fault returned $no_tags_status, want 97" >&2; exit 1; }
grep -q 'clear-tags' "$tmp/no-tags"

if "$rollout" --app argus --environment prod --image example/argus:test \
  --project example --dry-run --current-traffic rev-a=70 >/dev/null 2>&1; then
  echo "dry-run accepted a traffic allocation that does not total 100" >&2
  exit 1
fi

echo "cloud-run rollout command plans and rollback faults passed"
