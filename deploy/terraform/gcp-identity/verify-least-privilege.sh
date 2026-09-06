#!/usr/bin/env bash
# Runtime least privilege. Every case runs as a real workload identity via
# service-account impersonation; nothing here uses a service-account key file.
set -uo pipefail
# Configuration comes from `terraform output` where it can, and from the
# environment otherwise, so this runs against whatever stack was applied.
: "${PROJECT:=$(terraform output -raw project_id 2>/dev/null || echo "${GOOGLE_PROJECT:-}")}"
: "${PN:=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)' 2>/dev/null)}"
: "${POOL:=c10-deploy-pool}"
: "${PREFIX:=c10}"
if [[ -z "${PROJECT:-}" || -z "${PN:-}" ]]; then
  echo "set PROJECT (and optionally PN, POOL, PREFIX), or run this from an applied stack" >&2
  exit 2
fi
: "${TGB:=${PREFIX}-tollgate-state-${BUCKET_SUFFIX:?set BUCKET_SUFFIX to the applied state_bucket_suffix}}"
: "${ARB:=${PREFIX}-argus-state-${BUCKET_SUFFIX}}"
TGSA="${PREFIX}-tollgate-rt@$PROJECT.iam.gserviceaccount.com"
ARSA="${PREFIX}-argus-rt@$PROJECT.iam.gserviceaccount.com"
DPSA="${PREFIX}-deployer@$PROJECT.iam.gserviceaccount.com"
FAILED=0; TMP=$(mktemp -d)

# gcloud storage cp performs a bucket-level storage.objects.list before writing,
# which a prefix-conditioned object grant deliberately cannot satisfy. A real
# SDK client issues a direct object upload, so the object-write cases use the
# JSON API directly, which is what the runtime actually does.
tok_for() { gcloud auth print-access-token --impersonate-service-account="$1" 2>/dev/null; }
urlq() { python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }
put_case() { # want as bucket object label
  local want="$1" as="$2" bkt="$3" obj="$4" label="$5" code got mark
  code=$(curl -sS -o /tmp/c10put.$$ -w '%{http_code}' -X POST \
    "https://storage.googleapis.com/upload/storage/v1/b/$bkt/o?uploadType=media&name=$(urlq "$obj")" \
    -H "Authorization: Bearer $(tok_for "$as")" -H 'Content-Type: text/plain' --data-binary 'c10-state')
  got=DENIED; [[ "$code" == "200" ]] && got=ALLOWED
  mark=FAIL; [[ "$got" == "$want" ]] && mark=ok; [[ $mark == FAIL ]] && FAILED=1
  printf '[%-4s] expect=%-7s got=%-7s  %s\n' "$mark" "$want" "$got" "$label"
  [[ "$got" == DENIED ]] && printf '        http %s: %s\n' "$code" \
    "$(python3 -c "import json;print(json.load(open('/tmp/c10put.$$'))['error']['message'])" 2>/dev/null | cut -c1-150)"
  rm -f /tmp/c10put.$$
}


case_() { # want as label cmd...
  local want="$1" as="$2" label="$3"; shift 3
  local out rc
  out=$("$@" --impersonate-service-account="$as" 2>&1); rc=$?
  local got=DENIED; [[ $rc -eq 0 ]] && got=ALLOWED
  local mark=FAIL; [[ "$got" == "$want" ]] && mark=ok; [[ $mark == FAIL ]] && FAILED=1
  printf '[%-4s] expect=%-7s got=%-7s  %s\n' "$mark" "$want" "$got" "$label"
  if [[ "$got" == DENIED ]]; then
    printf '        %s\n' "$(printf '%s' "$out" | grep -oiE '(PERMISSION_DENIED|does not have [a-z.]+ access|Permission .[a-z.]+. denied[^.]*|403|401|forbidden)[^\n]{0,140}' | head -1 | cut -c1-170)"
  fi
}
echo "===================== c10-tollgate-rt (Tollgate runtime) ====================="
case_ ALLOWED "$TGSA" "read its OWN secret  ${PREFIX}-tollgate-upstream-key" \
  gcloud secrets versions access latest --secret=${PREFIX}-tollgate-upstream-key --project=$PROJECT
case_ DENIED  "$TGSA" "read ANOTHER app's secret  ${PREFIX}-argus-model-key" \
  gcloud secrets versions access latest --secret=${PREFIX}-argus-model-key --project=$PROJECT
case_ DENIED  "$TGSA" "read ANOTHER app's secret  ${PREFIX}-argus-supabase-key" \
  gcloud secrets versions access latest --secret=${PREFIX}-argus-supabase-key --project=$PROJECT
case_ DENIED  "$TGSA" "enumerate every secret in the project" \
  gcloud secrets list --project=$PROJECT
printf 'rotated-by-the-runtime' > "$TMP/rot"
case_ DENIED  "$TGSA" "ROTATE its own secret (add a version)" \
  gcloud secrets versions add ${PREFIX}-tollgate-upstream-key --data-file="$TMP/rot" --project=$PROJECT
case_ DENIED  "$TGSA" "DESTROY the version it can read" \
  gcloud secrets versions destroy 1 --secret=${PREFIX}-tollgate-upstream-key --project=$PROJECT --quiet
echo
case_ DENIED  "$TGSA" "enumerate every bucket in the project" \
  gcloud storage buckets list --project=$PROJECT
case_ DENIED  "$TGSA" "read ANOTHER bucket       gs://$ARB/" \
  gcloud storage ls "gs://$ARB/" --project=$PROJECT
put_case ALLOWED "$TGSA" "$TGB" "tollgate/state.json"      "write INSIDE its prefix    gs://\$TGB/tollgate/state.json"
put_case ALLOWED "$TGSA" "$TGB" "tollgate/nested/deep/a"   "write deeper in its prefix gs://\$TGB/tollgate/nested/deep/a"
put_case DENIED  "$TGSA" "$TGB" "escape.json"              "write at bucket ROOT       gs://\$TGB/escape.json"
put_case DENIED  "$TGSA" "$TGB" "argus/state.json"         "write another tenant path  gs://\$TGB/argus/state.json"
put_case DENIED  "$TGSA" "$TGB" "tollgate-evil/x"          "prefix look-alike, no /    gs://\$TGB/tollgate-evil/x"
put_case DENIED  "$TGSA" "$TGB" "Tollgate/case.json"       "prefix case variant        gs://\$TGB/Tollgate/case.json"
put_case DENIED  "$TGSA" "$ARB" "tollgate/state.json"      "write to ANOTHER bucket    gs://\$ARB/tollgate/state.json"

echo
case_ DENIED  "$TGSA" "LATERAL: mint a token for c10-argus-rt" \
  gcloud auth print-access-token "$ARSA"
echo
echo "===================== c10-argus-rt (Argus runtime) ====================="
case_ ALLOWED "$ARSA" "read its OWN secret   ${PREFIX}-argus-model-key" \
  gcloud secrets versions access latest --secret=${PREFIX}-argus-model-key --project=$PROJECT
case_ ALLOWED "$ARSA" "read its OWN secret   ${PREFIX}-argus-supabase-key" \
  gcloud secrets versions access latest --secret=${PREFIX}-argus-supabase-key --project=$PROJECT
case_ DENIED  "$ARSA" "read Tollgate's secret ${PREFIX}-tollgate-upstream-key" \
  gcloud secrets versions access latest --secret=${PREFIX}-tollgate-upstream-key --project=$PROJECT
case_ DENIED  "$ARSA" "read Tollgate's bucket gs://$TGB/tollgate/" \
  gcloud storage ls "gs://$TGB/tollgate/" --project=$PROJECT
echo
echo "===================== c10-deployer (deployment identity) ====================="
case_ DENIED  "$DPSA" "read a RUNTIME secret  ${PREFIX}-tollgate-upstream-key" \
  gcloud secrets versions access latest --secret=${PREFIX}-tollgate-upstream-key --project=$PROJECT
case_ DENIED  "$DPSA" "read a RUNTIME secret  ${PREFIX}-argus-model-key" \
  gcloud secrets versions access latest --secret=${PREFIX}-argus-model-key --project=$PROJECT
case_ DENIED  "$DPSA" "read runtime state     gs://$TGB/tollgate/" \
  gcloud storage ls "gs://$TGB/tollgate/" --project=$PROJECT
case_ DENIED  "$DPSA" "list the project's IAM policy" \
  gcloud projects get-iam-policy $PROJECT
rm -rf "$TMP"; exit $FAILED
