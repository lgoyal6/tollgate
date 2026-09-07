#!/usr/bin/env bash
# Canary a Tollgate or Argus Cloud Run revision. The rollback snapshot includes
# every revision allocation and tag that existed before deploy changed traffic.
set -Eeuo pipefail

app=""
environment=""
image=""
project=""
region="us-central1"
canary_percent=10
observe_seconds=60
seed_failure=false
dry_run=false
prior_traffic=""
prior_tags=""
dry_fail_at=""
dry_interrupt_at=""

usage() {
  cat <<'EOF'
usage: scripts/cloud-run-rollout.sh --app tollgate|argus --environment stage|prod \
  --image IMAGE --project PROJECT [--region REGION] [--canary-percent 1..49] \
  [--observe-seconds N] [--seed-failure]

Dry run:
  --dry-run --current-traffic REVISION=PERCENT[,REVISION=PERCENT...] \
  [--current-tags TAG=REVISION[,TAG=REVISION...]] \
  [--dry-run-fail-at STEP | --dry-run-interrupt-at STEP]

Dry-run fault steps: deploy, canary-update, canary-probe, observe,
promote-update, tag-cleanup.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --app) app="${2:-}"; shift 2 ;;
    --environment) environment="${2:-}"; shift 2 ;;
    --image) image="${2:-}"; shift 2 ;;
    --project) project="${2:-}"; shift 2 ;;
    --region) region="${2:-}"; shift 2 ;;
    --canary-percent) canary_percent="${2:-}"; shift 2 ;;
    --observe-seconds) observe_seconds="${2:-}"; shift 2 ;;
    --current-traffic) prior_traffic="${2:-}"; shift 2 ;;
    --current-tags) prior_tags="${2:-}"; shift 2 ;;
    --seed-failure) seed_failure=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    --dry-run-fail-at) dry_fail_at="${2:-}"; shift 2 ;;
    --dry-run-interrupt-at) dry_interrupt_at="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$app" in
  tollgate) service="tollgate-gateway-${environment}"; probe_path="/" ;;
  argus) service="argus-backend-${environment}"; probe_path="/openapi.json" ;;
  *) echo "--app must be tollgate or argus" >&2; exit 2 ;;
esac
case "$environment" in stage|prod) ;; *) echo "--environment must be stage or prod" >&2; exit 2 ;; esac
[ -n "$image" ] || { echo "--image is required" >&2; exit 2; }
[ -n "$project" ] || { echo "--project is required" >&2; exit 2; }
case "$canary_percent" in *[!0-9]*|'') echo "--canary-percent must be an integer from 1 to 49" >&2; exit 2 ;; esac
if [ "$canary_percent" -lt 1 ] || [ "$canary_percent" -gt 49 ]; then
  echo "--canary-percent must be an integer from 1 to 49" >&2
  exit 2
fi
case "$observe_seconds" in *[!0-9]*|'') echo "--observe-seconds must be a non-negative integer" >&2; exit 2 ;; esac

fault_steps=" deploy canary-update canary-probe observe promote-update tag-cleanup "
for value in "$dry_fail_at" "$dry_interrupt_at"; do
  if [ -n "$value" ] && [[ "$fault_steps" != *" $value "* ]]; then
    echo "unknown dry-run fault step: $value" >&2
    exit 2
  fi
done
if [ -n "$dry_fail_at" ] && [ -n "$dry_interrupt_at" ]; then
  echo "choose only one dry-run fault control" >&2
  exit 2
fi
if ! $dry_run && { [ -n "$dry_fail_at" ] || [ -n "$dry_interrupt_at" ]; }; then
  echo "dry-run fault controls require --dry-run" >&2
  exit 2
fi

validate_assignments() {
  value="$1"
  allow_empty="$2"
  if [ -z "$value" ]; then
    $allow_empty && return 0
    return 1
  fi
  IFS=',' read -r -a entries <<<"$value"
  for entry in "${entries[@]}"; do
    name="${entry%%=*}"
    assigned="${entry#*=}"
    [ -n "$name" ] && [ "$assigned" != "$entry" ] && [ -n "$assigned" ] || return 1
  done
}

validate_traffic() {
  validate_assignments "$1" false || return 1
  total=0
  IFS=',' read -r -a entries <<<"$1"
  for entry in "${entries[@]}"; do
    percent="${entry#*=}"
    case "$percent" in *[!0-9]*|'') return 1 ;; esac
    total=$((total + percent))
  done
  [ "$total" -eq 100 ]
}

if $dry_run; then
  validate_traffic "$prior_traffic" || {
    echo "--dry-run requires --current-traffic with the complete rollback allocation" >&2
    exit 2
  }
  validate_assignments "$prior_tags" true || { echo "invalid --current-tags" >&2; exit 2; }
fi

show() { printf '%q ' "$@"; printf '\n'; }
run_step() {
  step="$1"
  shift
  if $dry_run; then
    show "$@"
    if [ "$dry_interrupt_at" = "$step" ]; then
      echo "simulating interrupt at $step" >&2
      kill -INT $$
    fi
    if [ "$dry_fail_at" = "$step" ]; then
      echo "simulating command failure at $step" >&2
      return 97
    fi
    return 0
  fi
  "$@"
}

describe=(gcloud run services describe "$service" --project "$project" --region "$region" --format=json)
if ! $dry_run; then
  service_json="$("${describe[@]}")"
  prior_traffic="$(jq -r '[.status.traffic[] | select(.revisionName != null and .percent != null and .percent > 0) | "\(.revisionName)=\(.percent)"] | join(",")' <<<"$service_json")"
  prior_tags="$(jq -r '[.status.traffic[] | select(.revisionName != null and .tag != null) | "\(.tag)=\(.revisionName)"] | join(",")' <<<"$service_json")"
  validate_traffic "$prior_traffic" || {
    echo "could not capture the current traffic allocation" >&2
    exit 1
  }
fi

scale_prior_traffic() {
  target="$1"
  spec="$2"
  IFS=',' read -r -a entries <<<"$spec"
  count="${#entries[@]}"
  left="$target"
  output=""
  for ((i = 0; i < count; i++)); do
    revision="${entries[$i]%%=*}"
    percent="${entries[$i]#*=}"
    case "$percent" in *[!0-9]*|'') echo "invalid traffic percent in $spec" >&2; return 1 ;; esac
    if [ "$i" -eq $((count - 1)) ]; then
      scaled="$left"
    else
      scaled=$((percent * target / 100))
      left=$((left - scaled))
    fi
    if [ "$scaled" -gt 0 ]; then
      [ -z "$output" ] || output="${output},"
      output="${output}${revision}=${scaled}"
    fi
  done
  printf '%s' "$output"
}

remaining=$((100 - canary_percent))
scaled_prior="$(scale_prior_traffic "$remaining" "$prior_traffic")"
[ -n "$scaled_prior" ] || { echo "canary calculation removed every prior revision" >&2; exit 1; }

stamp="$(date -u +%Y%m%d%H%M%S)"
suffix="rollout-${stamp}"
rollout_tag="candidate-${stamp}"
new_revision="${service}-${suffix}"
canary_traffic="${new_revision}=${canary_percent},${scaled_prior}"
rollback_armed=false

restore_prior() {
  echo "restoring traffic: ${prior_traffic}" >&2
  restore=(gcloud run services update-traffic "$service" --project "$project" --region "$region" \
    --to-revisions "$prior_traffic")
  if [ -n "$prior_tags" ]; then
    restore+=(--set-tags "$prior_tags")
  else
    restore+=(--clear-tags)
  fi
  restore+=(--quiet)
  if $dry_run; then show "${restore[@]}"; else "${restore[@]}"; fi
}

finish_with_rollback() {
  status="$1"
  trap - ERR INT TERM
  if $rollback_armed; then restore_prior || true; fi
  exit "$status"
}
trap 'finish_with_rollback $?' ERR
trap 'finish_with_rollback 130' INT
trap 'finish_with_rollback 143' TERM

# Deploying with a tag changes the service traffic metadata even with no
# percentage assigned. Arm rollback before this first mutation.
rollback_armed=true
run_step deploy gcloud run deploy "$service" --project "$project" --region "$region" \
  --image "$image" --no-traffic --tag "$rollout_tag" --revision-suffix "$suffix" --quiet

if ! $dry_run; then
  service_json="$("${describe[@]}")"
  observed="$(jq -r '.status.latestReadyRevisionName // empty' <<<"$service_json")"
  [ "$observed" = "$new_revision" ] || {
    echo "latest ready revision is ${observed:-absent}, want $new_revision" >&2
    false
  }
fi

run_step canary-update gcloud run services update-traffic "$service" --project "$project" --region "$region" \
  --to-revisions "$canary_traffic" --quiet

# Probe the rollout tag only after the traffic mutation succeeds. This proves
# the exact candidate remains reachable while rollback is already armed.
if $dry_run; then
  run_step canary-probe probe-tagged-revision "$service" "$rollout_tag" "$probe_path"
else
  service_json="$("${describe[@]}")"
  canary_url="$(jq -r --arg tag "$rollout_tag" '.status.traffic[] | select(.tag == $tag) | .uri // empty' <<<"$service_json")"
  [ -n "$canary_url" ] || { echo "rollout tag has no URL" >&2; false; }
  if [ "$app" = "argus" ]; then
    token="$(gcloud auth print-identity-token --audiences="$canary_url")"
    run_step canary-probe curl -fsS -o /dev/null -H "Authorization: Bearer $token" "${canary_url}${probe_path}"
  else
    status="$(curl -sS -o /dev/null -w '%{http_code}' "${canary_url}${probe_path}")"
    [ "$status" = "401" ] || { echo "Tollgate canary returned HTTP $status, want 401" >&2; false; }
  fi
fi

if $seed_failure; then
  echo "seeded failure after canary traffic shift" >&2
  false
fi

run_step observe sleep "$observe_seconds"
if ! $dry_run; then
  service_url="$("${describe[@]}" | jq -r '.status.url // empty')"
  [ -n "$service_url" ] || { echo "service has no URL after canary shift" >&2; false; }
  if [ "$app" = "argus" ]; then
    token="$(gcloud auth print-identity-token --audiences="$service_url")"
    curl -fsS -H "Authorization: Bearer $token" "${service_url}${probe_path}" >/dev/null
  else
    status="$(curl -sS -o /dev/null -w '%{http_code}' "${service_url}${probe_path}")"
    [ "$status" = "401" ] || { echo "Tollgate service returned HTTP $status, want 401" >&2; false; }
  fi
fi

run_step promote-update gcloud run services update-traffic "$service" --project "$project" --region "$region" \
  --to-revisions "${new_revision}=100" --quiet
run_step tag-cleanup gcloud run services update-traffic "$service" --project "$project" --region "$region" \
  --remove-tags "$rollout_tag" --quiet
rollback_armed=false
trap - ERR INT TERM
echo "promoted ${new_revision} on ${service}"
