# Accepting OIDC access tokens

tollgate authenticates two credential types. Its own API key,
`tg_<id>_<secret>`, verified against a hash in Postgres; and a JWS-signed
access token from a configured identity provider, verified against that
provider's published keys. They are told apart by shape - a JWS is three
dot-separated segments and a tollgate key never contains a dot - so neither
path can be used as an oracle for the other.

Leaving `OIDC_ISSUERS` unset means the token path is never built, and the
gateway behaves exactly as it did before this existed.

## Configuration

```sh
export OIDC_ISSUERS='[
  {
    "issuer":    "https://acme.eu.auth0.com/",
    "jwks_url":  "https://acme.eu.auth0.com/.well-known/jwks.json",
    "audience":  "https://api.example.com",
    "tenant_id": "acme"
  }
]'
export OIDC_JWKS_TTL=10m          # how long a fetched key set is served
export OIDC_TOKEN_CACHE_TTL=30s   # 0 disables the verified-token cache
```

For certificate-bound tokens, the listener also needs to terminate TLS and be
willing to ask for a client certificate:

```sh
export TLS_CERT_FILE=/etc/tollgate/tls.crt
export TLS_KEY_FILE=/etc/tollgate/tls.key
export TLS_CLIENT_CA_FILE=/etc/tollgate/client-ca.pem
```

Every field of an issuer entry is required. There is no sensible default for
any of them, and a defaulted `audience` or `tenant_id` would be a silent
widening of trust.

### Why issuers are not in Postgres

Tenants, routes and API keys live in Postgres and hot-reload through
`LISTEN/NOTIFY`. Issuers do not, and the difference is not an oversight.

An issuer entry is a trust anchor. It says which signing keys may mint a
credential for which tenant. If it lived in the table an operator edits
through the admin API, then anyone who can write a row could point a tenant at
an identity provider they control and mint tokens for it. That is a privilege
escalation, not a configuration change. In the process environment, changing
it takes a deploy.

The cost is real and worth stating: adding an issuer restarts the gateway,
where adding a tenant does not.

## What is verified, and in what order

The order is chosen so that nothing an attacker sends can make the gateway do
expensive work.

| Step | Cost | Why here |
|---|---|---|
| Length check | string compare | An 8 KB cap applied before any base64 decode or allocation |
| Segment split, base64 decode | bytes | Raw and *strict*, so one token has exactly one spelling |
| Header policy | JSON parse | `alg`, `kid`, refusal of `jwk`/`jku`/`x5u`/`x5c`/`crit`/`enc`, `typ` |
| `iss` lookup | map lookup | Selects the issuer config, and therefore the key set |
| `exp`, `nbf`, `iat` | integer compare | An expired token must not cost an RSA verification |
| `aud`, `sub` | string compare | A token minted for another resource server is not spendable here |
| `cnf` binding | one SHA-256 | Only if the token claims to be certificate-bound |
| Key lookup | map, or a JWKS fetch | The first step that can touch the network |
| Signature | ~33 µs (RS256) | Last, because it is the most expensive thing here |

There is a test asserting an expired token costs zero JWKS fetches.

## Three design decisions

**No symmetric algorithms exist in the package.** There is no HMAC code path
at all. The RS256-to-HS256 confusion attack works by getting a verifier to
treat an RSA public key as an HMAC secret; it cannot be expressed against a
verifier that cannot compute an HMAC. This is a capability removed rather than
a check added, and checks are what get bypassed.

**The algorithm comes from the key, not the token.** A JWK declares what it may
be used for, explicitly through its own `alg` member or implicitly through its
curve. The token's `alg` header is only ever compared against that; it never
selects a verifier. This is stricter than the usual `WithValidMethods`-style
allowlist in a way that matters: an allowlist that includes both RS256 and
PS256 will accept either against the same RSA key, whatever the JWKS says the
key is for.

**A key is found by `kid` or not at all.** Trying every key in the set until one
verifies makes the set as weak as its weakest member and turns an unknown
`kid` into N public key operations.

## Key rotation, and not being a request amplifier

A key set moves in ways that are all hostile to a naive cache.

Rotation introduces a `kid` the cache has never seen, and tokens carrying it
arrive long before any TTL runs out. A cache that only refreshes on a timer
rejects every one of them. So a miss has to be able to trigger a fetch.

But a `kid` is an attacker-controlled string, so a stream of tokens with random
kids becomes a request amplifier aimed at the identity provider. A miss
therefore triggers **at most one fetch per 30 seconds**: 500 unknown kids in
one window cost one request, and a genuine rotation is still picked up once
the window passes. Concurrent callers collapse onto a single in-flight fetch,
so a cold cache behind a burst is one request rather than a herd.

A failed refresh keeps serving the set already in hand. Failing closed would
turn a thirty second provider blip into a total authentication outage.
`tollgate_oidc_keys_stale` is 1 for exactly as long as that is happening, and
it is worth alerting on: it is the window in which a key revoked at the
provider is still trusted here.

## The verified-token cache, and what it costs

An RSA-2048 verification is 33.4 µs of CPU on an M3 Pro, paid on every
request, for a token that does not change between them. Caching the result by
the token's SHA-256 makes that 456 ns.

What it costs is a window in which the gateway honours a token that should no
longer work. The window is bounded twice:

- **By the token.** An entry's deadline is `min(now + TTL, exp)`, so a cached
  entry never outlives the token that made it.
- **By key liveness.** A cache hit re-checks that the `kid` which signed the
  token is still in the issuer's published key set. Pulling a key from the
  JWKS is the only revocation a stateless OIDC deployment actually offers, and
  without this check the cache would extend the blast radius of a compromised
  signing key from one key set refresh out to the expiry of every token that
  key ever signed.

So the compromised-key response time is bounded by `OIDC_JWKS_TTL`, not by
`OIDC_TOKEN_CACHE_TTL`. `tollgate_oidc_token_cache_revocations_total` counts
how often that has actually fired.

It is not an LRU. An LRU reorders a list on every read, which puts a write lock
on the path the cache exists to make cheap. Instead: a size cap, expired
entries swept on insert, arbitrary eviction past the cap. The cost of evicting
the wrong entry is one RSA verification, which is what the cache was avoiding
anyway.

What none of this does is make a *stolen but still valid* token stop working.
Nothing stateless does.

## Certificate-bound tokens (RFC 8705)

A bearer token is spendable by whoever holds it. That is the format's largest
weakness: a token in a log, a proxy buffer or a browser extension is a working
credential.

A token carrying `cnf: {"x5t#S256": ...}` is bound to a client certificate.
The gateway checks the SHA-256 of the presented certificate's DER against that
claim, so the token is only spendable by the holder of the matching private
key.

The listener uses `VerifyClientCertIfGiven`:

- `RequireAndVerifyClientCert` would mean issuing a certificate to every
  caller before any of this is useful, including the ones authenticating with
  an API key. That is how mTLS ends up shelved.
- `RequestClientCert` is the dangerous middle setting. It asks for a
  certificate and does not verify it, which would hand the binding check a
  certificate nobody vouched for. Since the check compares a *thumbprint*
  rather than a signature, an attacker could then present the very certificate
  the stolen token names and be believed.

Optional-but-verified is what makes the thumbprint comparison mean anything.

The check is one-directional: a token *without* `cnf` is accepted over any
transport. The issuer decides which of its tokens are sender-constrained, and
a gateway that demanded `cnf` from everybody could accept tokens from almost
nobody.

## Testing

`internal/jwt/adversarial_test.go` holds thirty tokens an attacker would
actually send, each labelled with the bug class it belongs to. Every one must
be refused.

`internal/jwt/differential_test.go` runs the same corpus through
`github.com/golang-jwt/jwt` as a test-only dependency, configured the way a
careful engineer would configure it, and asserts two things: nothing here
accepts what golang-jwt refuses, and every disagreement is one where this
package is stricter and carries a written reason. Eleven of the thirty are
refused only here. The list is checked in both directions, so a case marked as
a divergence that golang-jwt starts refusing fails the test rather than
quietly rotting.

To be fair about the comparison: with `WithValidMethods` set, golang-jwt
refuses the HS256 confusion attack too. The claim is not that it is unsafe. It
is that its safety is a property of a call site remembering an option, and
this package's safety is a property of there being no HMAC code to reach.
