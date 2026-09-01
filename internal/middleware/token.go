package middleware

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/lgoyal6/tollgate/internal/jwt"
	"github.com/lgoyal6/tollgate/internal/store"
)

// TokenAuth is the OIDC half of the Auth middleware. A nil *TokenAuth turns
// it off, and a gateway deployed before it existed behaves exactly as it did:
// a three-segment credential then falls through to the API key path and is
// refused there for being malformed, which is the right answer.
type TokenAuth struct {
	Verifier *jwt.Verifier
	// Cache is optional. Without it every request pays a public key
	// operation; with it, a bounded revocation window buys about 70x. See
	// internal/jwt/cache.go.
	Cache *jwt.VerifiedCache
}

func (t *TokenAuth) verify(ctx context.Context, raw string, b jwt.Binding) (*jwt.Verified, error) {
	if t.Cache != nil {
		return t.Cache.Verify(ctx, t.Verifier, raw, b)
	}
	return t.Verifier.Verify(ctx, raw, b)
}

// bindingFor is what the transport can prove about the caller.
//
// Only the leaf certificate matters: RFC 8705 binds a token to the
// certificate the client actually authenticated with, not to anything further
// up its chain. Note that this is populated whenever a client certificate was
// presented at all; whether it was *verified* is a property of the listener's
// tls.Config, and internal/gateway sets VerifyClientCertIfGiven so an
// unverifiable one never reaches here.
func bindingFor(r *http.Request) jwt.Binding {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return jwt.Binding{}
	}
	var leaf *x509.Certificate = r.TLS.PeerCertificates[0]
	return jwt.Binding{PeerCert: leaf}
}

// tokenVerdict adapts a verified token onto the same two values the rest of
// the chain already reads: a tenant, and a key carrying scopes.
//
// The synthesized key has no secret, because there is no secret. The
// credential is the signature, and it was checked before this was built. It
// exists so that route scope enforcement, per-tenant rate limiting and usage
// accounting keep working unchanged rather than growing a second code path
// each.
func tokenVerdict(snap *store.Snapshot, v *jwt.Verified) (*store.Tenant, *store.APIKey, error) {
	tenant, ok := snap.Tenant(v.TenantID)
	if !ok {
		// The issuer is configured to map onto a tenant that does not exist.
		// An operator error rather than a caller error, but the caller still
		// gets the same opaque 401.
		return nil, nil, errTenantMissing
	}
	if !tenant.Enabled {
		return nil, nil, errTenantDisabled
	}
	return tenant, &store.APIKey{
		// Namespaced so a token subject can never collide with a real key id
		// in a log, a usage record or a metric.
		ID:       "oidc:" + v.Claims.Subject,
		TenantID: tenant.ID,
		Scopes:   v.Claims.Scopes,
		Status:   store.KeyActive,
	}, nil
}

var (
	errTenantMissing  = errors.New("middleware: issuer maps to an unknown tenant")
	errTenantDisabled = errors.New("middleware: tenant disabled")
)

// tokenFailureReason labels an auth failure for the metric.
//
// Bounded by construction: every value below is a constant in this function,
// so nothing an attacker writes can become a Prometheus label.
func tokenFailureReason(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTooLarge):
		return "jwt_oversized"
	case errors.Is(err, jwt.ErrMalformed), errors.Is(err, jwt.ErrDuplicateField):
		return "jwt_malformed"
	case errors.Is(err, jwt.ErrUnsupportedAlg), errors.Is(err, jwt.ErrAlgMismatch):
		return "jwt_algorithm"
	case errors.Is(err, jwt.ErrHeaderKey), errors.Is(err, jwt.ErrCritical):
		return "jwt_header_policy"
	case errors.Is(err, jwt.ErrNoKeyID), errors.Is(err, jwt.ErrUnknownKey):
		return "jwt_unknown_key"
	case errors.Is(err, jwt.ErrKeysUnavailable):
		return "jwt_keys_unavailable"
	case errors.Is(err, jwt.ErrBadSignature):
		return "jwt_bad_signature"
	case errors.Is(err, jwt.ErrExpired), errors.Is(err, jwt.ErrNotYetValid), errors.Is(err, jwt.ErrFromTheFuture):
		return "jwt_time"
	case errors.Is(err, jwt.ErrAudience), errors.Is(err, jwt.ErrIssuerUnknown):
		return "jwt_wrong_party"
	case errors.Is(err, jwt.ErrNotBound):
		return "jwt_unbound_certificate"
	case errors.Is(err, errTenantMissing):
		return "jwt_tenant_unknown"
	case errors.Is(err, errTenantDisabled):
		return "tenant_disabled"
	default:
		return "jwt_other"
	}
}
