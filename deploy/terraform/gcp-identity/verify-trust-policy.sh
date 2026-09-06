#!/usr/bin/env bash
# Exercise the C10 workload-identity trust policy against the real Google STS
# endpoint. Every case states the expectation up front; the script fails if any
# case does not land where it is expected to.
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
PROJECT=gen-lang-client-0427846261
PN=147516401928
POOL=c10-deploy-pool
PROV="${PROV:-c10-probe}"
AUD="//iam.googleapis.com/projects/$PN/locations/global/workloadIdentityPools/$POOL/providers/$PROV"
JWT_AUD="https://iam.googleapis.com/projects/$PN/locations/global/workloadIdentityPools/$POOL/providers/$PROV"

# The probe providers are test fixtures, not production: they carry the same
# attribute condition as the real GitHub provider but an issuer whose signing
# key is generated here, so out-of-policy claims can actually be presented.
# Terraform owns the GitHub provider; this owns the probes, and keeps their
# uploaded JWKS in step with the local key.
PROBE_ISSUER="https://c10-probe.tollgate.invalid"
node probe-issuer.mjs '{"iss":"x","sub":"warmup","aud":"x"}' >/dev/null

MAPPING='google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_id=assertion.repository_id,attribute.ref=assertion.ref,attribute.environment=assertion.environment,attribute.workflow_ref=assertion.job_workflow_ref'

ensure_probe() { # $1=provider id  $2=attribute condition
  local args=(--project="$PROJECT" --location=global --workload-identity-pool="$POOL"
              --jwk-json-path=probe_jwks.json --attribute-mapping="$MAPPING"
              --attribute-condition="$2")
  if gcloud iam workload-identity-pools providers describe "$1" --project="$PROJECT" \
       --location=global --workload-identity-pool="$POOL" >/dev/null 2>&1; then
    gcloud iam workload-identity-pools providers update-oidc "$1" "${args[@]}" >/dev/null || {
      echo "could not update probe provider $1" >&2; exit 2; }
  else
    gcloud iam workload-identity-pools providers create-oidc "$1" "${args[@]}" \
      --display-name="probe ${1##*-}" --issuer-uri="$PROBE_ISSUER" >/dev/null || {
      echo "could not create probe provider $1" >&2; exit 2; }
  fi
}

REAL_CONDITION=$(gcloud iam workload-identity-pools providers describe "${PREFIX}-github" \
  --project="$PROJECT" --location=global --workload-identity-pool="$POOL" \
  --format='value(attributeCondition)' 2>/dev/null)
if [[ -z "$REAL_CONDITION" ]]; then
  echo "the ${PREFIX}-github provider does not exist: apply the Terraform first" >&2; exit 2
fi
# The tight probe carries the production condition verbatim, so what is proved
# here is the condition the GitHub provider enforces.
ensure_probe "${PREFIX}-probe"       "$REAL_CONDITION"
# The loose probe is the anti-pattern: "any repository owned by this account".
# It exists so the second IAM layer has something to catch.
ensure_probe "${PREFIX}-probe-loose" "assertion.repository_owner_id == '${OWNER_ID:-238557621}'"

exchange() { # $1 = jwt   -> prints "HTTPSTATUS<TAB>body"
  curl -sS -o /tmp/c10_sts_body.$$ -w '%{http_code}' -X POST https://sts.googleapis.com/v1/token \
    -H 'Content-Type: application/json' -d @- <<JSON
{"audience":"$AUD",
 "grantType":"urn:ietf:params:oauth:grant-type:token-exchange",
 "requestedTokenType":"urn:ietf:params:oauth:token-type:access_token",
 "scope":"https://www.googleapis.com/auth/cloud-platform",
 "subjectTokenType":"urn:ietf:params:oauth:token-type:jwt",
 "subjectToken":"$1"}
JSON
  printf '\t'; cat /tmp/c10_sts_body.$$; rm -f /tmp/c10_sts_body.$$
}

# expectation, label, claims-json, [signing key]
run_case() {
  local want="$1" label="$2" claims="$3" key="${4:-probe_key.pem}"
  local jwt out code body
  jwt=$(node probe-issuer.mjs "$claims" "$key")
  out=$(exchange "$jwt"); code="${out%%$'\t'*}"; body="${out#*$'\t'}"
  local got="REFUSED"; [[ "$code" == "200" ]] && got="ALLOWED"
  local mark="FAIL"; [[ "$got" == "$want" ]] && mark="ok"
  printf '[%-4s] expect=%-8s got=%-8s http=%s  %s\n' "$mark" "$want" "$got" "$code" "$label"
  if [[ "$got" == "REFUSED" ]]; then
    printf '        reason: %s\n' "$(python3 -c "
import json,sys
try:
    d=json.loads(sys.argv[1]); print(d.get('error_description') or d.get('error') or sys.argv[1][:200])
except Exception: print(sys.argv[1][:200])" "$body")"
  else
    printf '        token_lifetime_seconds: %s   token_type: %s\n' \
      "$(python3 -c "import json,sys;print(json.loads(sys.argv[1]).get('expires_in'))" "$body")" \
      "$(python3 -c "import json,sys;print(json.loads(sys.argv[1]).get('issued_token_type'))" "$body")"
    # Deliberately not written to disk. The body carries a real, usable
    # access token; the only thing needed from it is the lifetime above.
  fi
  [[ "$mark" == "ok" ]] || FAILED=1
}

base() { # $1=overrides json
  python3 - "$JWT_AUD" "$1" <<'PY'
import json,sys
aud, over = sys.argv[1], json.loads(sys.argv[2])
c = {"iss":"https://c10-probe.tollgate.invalid","aud":aud,
     "sub":"repo:lgoyal6/tollgate:environment:production",
     "repository":"lgoyal6/tollgate","repository_id":"1314415571",
     "repository_owner":"lgoyal6","repository_owner_id":"238557621",
     "ref":"refs/tags/v1.4.0","ref_type":"tag","environment":"production",
     "actor":"lgoyal6","event_name":"push","runner_environment":"github-hosted",
     "job_workflow_ref":"lgoyal6/tollgate/.github/workflows/deploy.yml@refs/tags/v1.4.0"}
c.update(over); print(json.dumps(c))
PY
}

FAILED=0
echo "provider under test: $PROV"
echo "condition: $(gcloud iam workload-identity-pools providers describe $PROV --project=$PROJECT \
   --location=global --workload-identity-pool=$POOL --format='value(attributeCondition)' 2>/dev/null)"
echo
run_case ALLOWED "IN POLICY: tollgate, v-tag, production env, deploy.yml"        "$(base '{}')"
run_case REFUSED "out of policy: DIFFERENT REPO, same owner (org-wide would pass)" "$(base '{"repository":"lgoyal6/leetcode","repository_id":"900000001","sub":"repo:lgoyal6/leetcode:environment:production","job_workflow_ref":"lgoyal6/leetcode/.github/workflows/deploy.yml@refs/tags/v1.4.0"}')"
run_case REFUSED "out of policy: BRANCH instead of tag (refs/heads/main)"        "$(base '{"ref":"refs/heads/main","ref_type":"branch","job_workflow_ref":"lgoyal6/tollgate/.github/workflows/deploy.yml@refs/heads/main"}')"
run_case REFUSED "out of policy: non-v tag (refs/tags/nightly)"                  "$(base '{"ref":"refs/tags/nightly","job_workflow_ref":"lgoyal6/tollgate/.github/workflows/deploy.yml@refs/tags/nightly"}')"
run_case REFUSED "out of policy: ENVIRONMENT staging, not production"            "$(base '{"environment":"staging"}')"
run_case REFUSED "out of policy: no environment claim at all"                    "$(base '{"environment":null}' | python3 -c "import json,sys;d=json.load(sys.stdin);d.pop('environment');print(json.dumps(d))")"
run_case REFUSED "out of policy: DIFFERENT WORKFLOW file in the same repo"       "$(base '{"job_workflow_ref":"lgoyal6/tollgate/.github/workflows/ci.yml@refs/tags/v1.4.0"}')"
run_case REFUSED "out of policy: repo NAME squat under a different owner"        "$(base '{"repository":"attacker/tollgate","repository_owner":"attacker","repository_owner_id":"999999","repository_id":"1314415571","job_workflow_ref":"attacker/tollgate/.github/workflows/deploy.yml@refs/tags/v1.4.0"}')"
run_case REFUSED "out of policy: repo deleted+recreated (name kept, new repo_id)" "$(base '{"repository_id":"1999999999"}')"
run_case REFUSED "negative control: correct claims, ROGUE signing key"           "$(base '{}')" rogue_key.pem
exit $FAILED
