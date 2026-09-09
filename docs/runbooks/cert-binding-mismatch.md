# Runbook: certificate binding mismatch

## What fires

`event_type: cert_mismatch`, `control: rfc8705_certificate_binding`,
`outcome: rejected`.

An issuer bound a token to a specific client certificate with RFC 8705's
`cnf` claim, and the token arrived over a connection that presented a
different certificate, or none. `internal/jwt` refused it; the caller got the
same opaque 401 every token rejection gets.

**The control held.** This event is the record of an attack that did not
work, which is the most useful kind to have: somebody is holding a valid
token they cannot use.

## Read these fields

| field | what it tells you |
|---|---|
| `evidence.presented_thumbprint` | the SHA-256 of the certificate actually presented, or `none`. |
| `evidence.client_certificate_presented` | `false` means the token was replayed over a connection with no client certificate at all. |
| `tenant_id` | `unauthenticated`, always. See below. |
| `route` | `unmatched`, always: the request was refused before routing. |

The thumbprint the token *demanded* is deliberately absent. The verifier does
not return it on failure, because every token rejection here answers with one
identical 401 and a verifier that handed back the expected value would turn
this path into an oracle for what a stolen token is bound to.

## Confirm it

1. Open `trace_id`. The span is the request's own, so it carries the method,
   path, host and the 401.
2. Count them. One is a misconfigured client. A run of them from one source,
   inside a short window, is somebody trying certificates.
3. Ask the identity provider which subject that `cnf` thumbprint belongs to.
   The gateway cannot tell you, by design.

## Recovery action

**Rotate key.** The token is loose: somebody has it who is not its holder.
Have the issuer rotate the credential for that subject, and re-issue with a
`cnf` bound to the new client certificate. Nothing needs doing on the gateway
- the binding check is already refusing it - so this is entirely an action at
the identity provider.

If the mismatch turns out to be a legitimate client that changed its
certificate without the issuer being told, the fix is at the issuer too: mint
a token bound to the certificate the client now presents.

## What this runbook does not cover

- **`tenant_id` is always `unauthenticated`.** The credential was refused, so
  no tenant was resolved, so the event cannot say whose token it was. That is
  the correct behaviour and it is also a real limit: correlating these events
  to an account needs the issuer's own logs, keyed by the time and the
  thumbprint.
- **A token with no `cnf` claim never reaches this check.** Binding is
  one-directional by design: the issuer decides which of its tokens are
  sender-constrained, and the gateway honours that. An unbound token replayed
  from anywhere is scenario one, not this one, and it is admitted.
- **Whether the certificate was valid is not this check's business.** The
  listener's `tls.Config` decides that (`VerifyClientCertIfGiven`), before
  anything here runs. This check only asks whether the certificate presented
  is the one the token names.
