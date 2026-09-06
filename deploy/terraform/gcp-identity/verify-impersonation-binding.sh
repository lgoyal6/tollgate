#!/usr/bin/env bash
# Layer 2: even when a token clears the provider's attribute condition, the
# service account's own workloadIdentityUser binding decides which identity it
# may become. The binding is principalSet .../attribute.repository/lgoyal6/tollgate.
set -uo pipefail
: "${PROJECT:=${GOOGLE_PROJECT:-}}"
: "${PN:=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)' 2>/dev/null)}"
: "${POOL:=c10-deploy-pool}"
: "${PREFIX:=c10}"
[[ -n "${PROJECT:-}" && -n "${PN:-}" ]] || { echo "set PROJECT" >&2; exit 2; }
SA="${PREFIX}-deployer@$PROJECT.iam.gserviceaccount.com"

fed() { # $1=provider $2=claims-json -> federated access token or "" 
  local aud="//iam.googleapis.com/projects/$PN/locations/global/workloadIdentityPools/$POOL/providers/$1"
  local jaud="https://iam.googleapis.com/projects/$PN/locations/global/workloadIdentityPools/$POOL/providers/$1"
  local jwt; jwt=$(node probe-issuer.mjs "$(python3 -c "
import json,sys; c=json.loads(sys.argv[1]); c['aud']=sys.argv[2]; print(json.dumps(c))" "$2" "$jaud")")
  curl -sS -X POST https://sts.googleapis.com/v1/token -H 'Content-Type: application/json' -d @- <<JSON | python3 -c "import json,sys;print(json.load(sys.stdin).get('access_token',''))"
{"audience":"$aud","grantType":"urn:ietf:params:oauth:grant-type:token-exchange",
 "requestedTokenType":"urn:ietf:params:oauth:token-type:access_token",
 "scope":"https://www.googleapis.com/auth/cloud-platform",
 "subjectTokenType":"urn:ietf:params:oauth:token-type:jwt","subjectToken":"$jwt"}
JSON
}

impersonate() { # $1=federated token
  curl -sS -o /tmp/c10_imp.$$ -w '%{http_code}' \
    -X POST "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$SA:generateAccessToken" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}'
  printf '\t'; cat /tmp/c10_imp.$$; rm -f /tmp/c10_imp.$$
}

IN='{"iss":"https://c10-probe.tollgate.invalid","sub":"repo:lgoyal6/tollgate:environment:production","repository":"lgoyal6/tollgate","repository_id":"1314415571","repository_owner":"lgoyal6","repository_owner_id":"238557621","ref":"refs/tags/v1.4.0","ref_type":"tag","environment":"production","job_workflow_ref":"lgoyal6/tollgate/.github/workflows/deploy.yml@refs/tags/v1.4.0"}'
OUT='{"iss":"https://c10-probe.tollgate.invalid","sub":"repo:lgoyal6/leetcode:environment:production","repository":"lgoyal6/leetcode","repository_id":"900000001","repository_owner":"lgoyal6","repository_owner_id":"238557621","ref":"refs/tags/v1.4.0","ref_type":"tag","environment":"production","job_workflow_ref":"lgoyal6/leetcode/.github/workflows/deploy.yml@refs/tags/v1.4.0"}'

FAILED=0
check() { # want label provider claims
  local want="$1" label="$2" t out code body
  t=$(fed "$3" "$4")
  if [[ -z "$t" ]]; then
    printf '[%-4s] %s\n        blocked at STS (never reached impersonation)\n' \
      "$( [[ $want == REFUSED ]] && echo ok || { FAILED=1; echo FAIL; } )" "$label"; return
  fi
  out=$(impersonate "$t"); code="${out%%$'\t'*}"; body="${out#*$'\t'}"
  local got=REFUSED; [[ "$code" == "200" ]] && got=ALLOWED
  local mark=FAIL; [[ "$got" == "$want" ]] && mark=ok; [[ $mark == FAIL ]] && FAILED=1
  printf '[%-4s] expect=%-8s got=%-8s http=%s  %s\n' "$mark" "$want" "$got" "$code" "$label"
  python3 - "$body" "$got" <<'PY'
import json,sys,datetime
b,got=sys.argv[1],sys.argv[2]
try: d=json.loads(b)
except Exception: print("        raw:",b[:200]); raise SystemExit
if got=="ALLOWED":
    exp=d["expireTime"].replace("Z","+00:00")
    life=(datetime.datetime.fromisoformat(exp)-datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    print(f"        deployment access token lifetime: ~{round(life)}s (expireTime {d['expireTime']})")
    print(f"        token prefix: {d['accessToken'][:12]}... (not printed in full)")
else:
    e=d.get("error",{})
    print(f"        reason: {e.get('status','')} {e.get('message','')[:220]}")
PY
}

echo "SA binding under test:"
gcloud iam service-accounts get-iam-policy "$SA" --project=$PROJECT --format=json 2>/dev/null \
  | python3 -c "import json,sys;[print('   ',b['role'],'->',m) for b in json.load(sys.stdin)['bindings'] for m in b['members']]"
echo
check ALLOWED "tight provider + in-policy repo -> may become c10-deployer"        ${PREFIX}-probe       "$IN"
check REFUSED "LOOSE provider + DIFFERENT repo -> cleared STS, refused at the SA" ${PREFIX}-probe-loose "$OUT"
check ALLOWED "loose provider + correct repo  -> allowed (binding matches)"       ${PREFIX}-probe-loose "$IN"
exit $FAILED
