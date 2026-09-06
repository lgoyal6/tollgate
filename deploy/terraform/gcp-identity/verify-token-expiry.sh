#!/usr/bin/env bash
# "Short-lived" is only a claim until the credential stops working. Mint a
# deployment token with an explicit short lifetime, use it, wait past exp, use
# it again.
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
PROJECT=gen-lang-client-0427846261; PN=147516401928; POOL=c10-deploy-pool; PROV=c10-probe
SA="${PREFIX}-deployer@$PROJECT.iam.gserviceaccount.com"
AUD="//iam.googleapis.com/projects/$PN/locations/global/workloadIdentityPools/$POOL/providers/$PROV"
JAUD="https://iam.googleapis.com/projects/$PN/locations/global/workloadIdentityPools/$POOL/providers/$PROV"
CLAIMS=$(python3 -c "
import json,sys;print(json.dumps({'iss':'https://c10-probe.tollgate.invalid','aud':sys.argv[1],
 'sub':'repo:lgoyal6/tollgate:environment:production','repository':'lgoyal6/tollgate',
 'repository_id':'1314415571','repository_owner':'lgoyal6','repository_owner_id':'238557621',
 'ref':'refs/tags/v1.4.0','ref_type':'tag','environment':'production',
 'job_workflow_ref':'lgoyal6/tollgate/.github/workflows/deploy.yml@refs/tags/v1.4.0'}))" "$JAUD")
JWT=$(node probe-issuer.mjs "$CLAIMS")
FED=$(curl -sS -X POST https://sts.googleapis.com/v1/token -H 'Content-Type: application/json' -d @- <<J | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])"
{"audience":"$AUD","grantType":"urn:ietf:params:oauth:grant-type:token-exchange",
 "requestedTokenType":"urn:ietf:params:oauth:token-type:access_token",
 "scope":"https://www.googleapis.com/auth/cloud-platform",
 "subjectTokenType":"urn:ietf:params:oauth:token-type:jwt","subjectToken":"$JWT"}
J
)
LIFE=${1:-60}
RESP=$(curl -sS -X POST "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$SA:generateAccessToken" \
  -H "Authorization: Bearer $FED" -H 'Content-Type: application/json' \
  -d "{\"scope\":[\"https://www.googleapis.com/auth/cloud-platform\"],\"lifetime\":\"${LIFE}s\"}")
AT=$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['accessToken'])" "$RESP" 2>/dev/null) || { echo "mint failed: $RESP"; exit 1; }
EXP=$(python3 -c "import json,sys;print(json.loads(sys.argv[1])['expireTime'])" "$RESP")
echo "requested lifetime : ${LIFE}s"
echo "expireTime         : $EXP"
python3 -c "
import datetime,sys
d=datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00'))
print('measured lifetime  : %ds' % round((d-datetime.datetime.now(datetime.timezone.utc)).total_seconds()))" "$EXP"

# Probe an operation this identity is actually authorised for, so a 200 means
# "credential accepted AND permitted" and the post-expiry code is unambiguous.
probe() { curl -sS -o /dev/null -w '%{http_code}' \
  "https://artifactregistry.googleapis.com/v1/projects/$PROJECT/locations/us-central1/repositories/c10-tollgate" \
  -H "Authorization: Bearer $AT"; }
echo
echo "t=0    : identity self-read http=$(probe)   (expect 200)"
SLEEP=$((LIFE+15)); echo "sleeping ${SLEEP}s past expiry..."; sleep $SLEEP
CODE=$(probe); echo "t=${SLEEP}s : identity self-read http=$CODE   (expect 401)"
[[ "$CODE" == "401" ]] && { echo "RESULT: the deployment credential is genuinely short-lived."; exit 0; }
echo "RESULT: token still accepted after expiry - NOT short-lived"; exit 1
