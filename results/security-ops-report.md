# tollgate security operations: detection evaluation

**Every frozen threshold held.**

## What this is, and what it is not

- Runs on: one local host, in a single Go process
- Traffic: synthetic scripted replay driven through the real middleware chain in process (httptest upstreams, in-memory config snapshot, in-memory rate limiter, in-memory spend ledger)
- no SOC, no on-call rotation, no paging
- no customer or production traffic
- no incident history: every incident in the results is one this harness caused on purpose, seconds earlier
- no prevention claim: this lane is detection only, and where a request was refused it was refused by a control that already existed
- no distributed claim: one process, one host, no Redis and no Postgres

Implemented: the events, the trace linkage, the append-only timeline, the correlator, the three detectors and the one allow-list control. Measured: the table below, on the single host above.

## Detection

| # | scenario | detected | delay ms | tenants | failed control | control held | recovery action | linkage |
|---|---|---|---|---|---|---|---|---|
| 1 | stolen_token_replay | yes | 0 | 1 | `rfc8705_certificate_binding` | no, allowed | revoke key | yes |
| 2 | cert_binding_mismatch | yes | 0 | 1 | `client_certificate_possession` | yes, refused | rotate key | yes |
| 3 | provider_key_anomaly | yes | 4 | 1 | `api_key_rotation_grace` | no, allowed | revoke key | yes |
| 4 | ssrf_metadata_attempt | yes | 0 | 1 | `upstream_metadata_allowlist` | yes, refused | reject route | yes |
| 5 | auth_rate_burst | yes | 0 | 1 | `tenant_admission_control` | yes, refused | disable tenant | yes |
| 6 | upstream_timeout_cascade | yes | 823 | 2 | `upstream_availability` | recovered, fell back | open breaker and fall back | yes |

Median detection delay across the malicious scenarios: **0 ms**. Maximum: **823 ms**.

milliseconds from the first event of an incident to the event that satisfied its rule, inside a script that controls its own timing. It is not a measurement of how fast anybody would notice: there is no alerting path and no human here. Scenarios whose rule is satisfied by their own first event are 0 ms by construction, which the manifest says up front.

## What each scenario sent

### 1. stolen_token_replay

stolen-token replay: a valid token presented again from a different peer identity

- three presentations of one unbound token
- presentations two and three come from a different client certificate
- 3 requests, 2 security events, 1 incident
- outcome recorded by the control that decided: `allowed`
- affected tenants: replay-co
- evidence: 2 events across 2 traces

### 2. cert_binding_mismatch

certificate-bound token presented with the wrong client certificate

- two presentations of a token the issuer bound to one certificate
- presented with a different certificate, which the binding control refuses
- 2 requests, 2 security events, 1 incident
- outcome recorded by the control that decided: `rejected`
- affected tenants: unauthenticated
- evidence: 2 events across 2 traces

### 3. provider_key_anomaly

rotated key still in its grace window, used far above baseline with a spend spike

- twenty requests on the same rotated key still inside its grace window
- the provider reports 20k in and 30k out per request: 510,000 micros each
- 20 requests, 21 security events, 1 incident
- outcome recorded by the control that decided: `allowed`
- affected tenants: spend-co
- evidence: 21 events across 20 traces

### 4. ssrf_metadata_attempt

a route whose upstream is a cloud instance metadata endpoint

- two requests on a route whose upstream is 169.254.169.254
- 2 requests, 2 security events, 1 incident
- outcome recorded by the control that decided: `rejected`
- affected tenants: meta-co
- evidence: 2 events across 2 traces

### 5. auth_rate_burst

a burst of rejected credentials and limiter refusals in a short window

- twelve credential presentations then twenty requests, on one tenant
- the twelve carry a real key id with somebody else's secret, and the twenty arrive inside one limiter window
- 32 requests, 26 security events, 2 incidents
- outcome recorded by the control that decided: `rejected`
- affected tenants: unauthenticated
- evidence: 12 events across 12 traces
- this scenario produced more than one incident, and the table above reports the first:
  - `auth_rate_burst#1` on `unauthenticated`: 12 events, detected at +0 ms, outcome `rejected`
  - `auth_rate_burst#2` on `burst-co`: 14 events, detected at +0 ms, outcome `rejected`

### 6. upstream_timeout_cascade

slow upstream, repeated timeouts, breaker opens, and a hedge carries the last request

- seven requests from two tenants to one upstream host, on the same routes in both legs
- the upstream never answers, so attempts time out, the shared breaker opens on both tenants, and the last request is carried by a hedge
- 7 requests, 9 security events, 1 incident
- outcome recorded by the control that decided: `fell_back`
- affected tenants: cascade-a, cascade-b
- evidence: 9 events across 4 traces

## The matched benign replay

66 requests, 20 security events, **0 alerts**. Request count matches the attack replay: yes.

| scenario | requests | events | alerts | what "without the attack" means here |
|---|---|---|---|---|
| stolen_token_replay | 3 | 0 | 0 | all three presentations come from the certificate that first used it |
| cert_binding_mismatch | 2 | 0 | 0 | presented with the certificate it is bound to |
| provider_key_anomaly | 20 | 20 | 0 | the provider reports 200 in and 100 out per request: 2,100 micros each |
| ssrf_metadata_attempt | 2 | 0 | 0 | two requests on a route whose upstream is a private address, which must NOT be refused |
| auth_rate_burst | 32 | 0 | 0 | all thirty two carry the tenant's own key, paced at 80ms so they stay inside the tenant's own policy |
| upstream_timeout_cascade | 7 | 0 | 0 | the same upstream answers, so nothing times out, the breaker stays closed and no hedge fires |

Events without alerts are the point: a rotated key in ordinary use still records key_rotation, and the rule declines to call it an incident.

## Determinism and integrity

- The replay ran 2 times. Normalized timelines identical: **yes**.
- Normalized digest sha256: `9d5252fe731e3b91cd14c93b88c70b9a460db90815b55b723f26b15686d67893`
- Timeline: 164 events recorded, 164 rebuilt from `results/security-ops-timeline.jsonl`, match: **yes**.

## How the harness was configured

- Chain: Recover, secops.Observe, RequestID, Metrics, Tracing, Auth, Router, RequestSize, RateLimit, Concurrency, Budget, proxy
- Omitted: CurrentAuthorization: it is a targeted Postgres query and these commands run with no database
- Breaker: opens at 6 samples, cooldown 250 ms (the shipped breaker at harness scale, so a scripted cascade takes under a second)
- Burst tenant policy: sliding window log, 6 requests per 250ms, identical in both legs
- Tracing: OpenTelemetry SDK tracer with no exporter: real span contexts, nothing leaves the process
- Storage: in-memory config snapshot, in-memory rate limiter, in-memory budget ledger, httptest upstreams

## Frozen thresholds

From `secops/manifest.json`, sha256 `9f675c4a84a1a0429082d67feee77411351f4a53d5875fc0347f1086ccb2da24`, frozen 2026-09-09.

| threshold | required | observed | pass |
|---|---|---|---|
| malicious scenarios detected | 6 of 6 | 6 of 6 | yes |
| alerts on the matched benign replay | 0 | 0 | yes |
| tenant, trace, control and outcome on every incident | complete | complete | yes |
| normalized replay identical across two runs | identical | identical | yes |
| the timeline rebuilt from its own log matches what was recorded | matches | matches | yes |
| the benign replay sent the same number of requests as the attack | equal | equal | yes |

The negative control is not in this table because it is a separate build: `scripts/run-security-ops-eval.sh` runs the harness again with `-tags secops_planted_fault` and requires that run to FAIL.
