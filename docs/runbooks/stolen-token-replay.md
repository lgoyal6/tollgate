# Runbook: stolen token replay

## What fires

`event_type: token_replay`, `control: oidc_token_replay_detector`.

A token id that this process has already seen was presented again, inside its
own lifetime, by a different peer. Peer means the SHA-256 thumbprint of the
client certificate when one was presented, and the caller's address when none
was.

## Read these fields

| field | what it tells you |
|---|---|
| `evidence.token_id` | `jti:<claim>` when the issuer set one, `tok:<hash>` when it did not. The raw token is never stored. |
| `evidence.first_seen_peer` | who presented it first. Treat this as the legitimate holder until you have a reason not to. |
| `evidence.peer` | who presented it this time. |
| `evidence.certificate_bound` | whether the token carried RFC 8705's `cnf` claim. |
| `outcome` | `allowed` on an unbound token. The detector does not refuse anything. |
| `tenant_id`, `key_id` | which tenant it authenticated as, and the token subject (`oidc:<sub>`). |

## Confirm it

1. Grep the timeline for `evidence.first_seen_peer` to find the first
   presentation's requests. Same subject, different peer, means one
   credential in two places.
2. Open `trace_id` in the trace backend. The span carries the same fields as
   span-event attributes, plus the upstream attempt and final status, so you
   can see what the replayed token actually bought.
3. Check `key_id`: an `oidc:` prefix means this is a token subject, not one
   of the gateway's own keys.

## Recovery action

**Revoke key.** For a token this means revoking at the issuer, not here: the
gateway does not mint these credentials and cannot recall one. Concretely,
in order of how quickly each binds:

1. Have the identity provider revoke the signing key, and confirm it leaves
   the JWKS. Cached verifications re-check key liveness, so this binds within
   `OIDC_JWKS_TTL`.
2. Have the provider stop issuing tokens for that subject.
3. If the tenant is spending, disable the tenant in the console. That is a
   blunt instrument and it stops the tenant's legitimate traffic too.

Then fix the cause: an issuer that binds its tokens to a client certificate
(`cnf` with `x5t#S256`) makes a stolen token useless to whoever stole it,
which is what the second scenario in `secops/manifest.json` demonstrates.

## What this runbook does not cover

- **It does not stop the replay.** An unbound bearer token is spendable by
  whoever holds it, and this gateway honours the issuer's decision not to
  bind it. The event says a credential is in two places; it is not a refusal.
- **It cannot see across processes or restarts.** The recent-seen set is in
  memory and bounded, so a replay against a different replica, or after a
  restart, is a first sighting. Multi-replica deployments will miss replays
  that do not land on the same pod.
- **An address is a hint, not proof.** A caller that presents no client
  certificate is tracked by address, and a legitimate client changing network
  looks the same as a thief. Weigh `evidence.certificate_bound` and
  `evidence.peer` accordingly: a `cert:` peer is proof of key possession, an
  `ip:` peer is not.
- **It is not evidence of theft on its own.** A shared service account used
  from two hosts produces exactly this event. Check whether the two peers are
  both meant to exist before treating it as an incident.
