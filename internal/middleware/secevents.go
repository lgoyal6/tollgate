package middleware

import (
	"net"
	"net/http"

	"github.com/lgoyal6/tollgate/internal/jwt"
	"github.com/lgoyal6/tollgate/internal/secops"
)

// This file is the adaptation between the auth path's existing verdicts and
// the security event stream. It lives beside the middleware rather than
// inside internal/secops because the mapping is about this chain's
// vocabulary - which failure reasons exist, what a peer identity is here -
// and internal/secops should not know either.
//
// Nothing here changes a decision. Every function is called on a path whose
// verdict is already fixed, after the metric has already been incremented,
// and each one returns nothing.

// recordAuthRejection records a refused credential. reason is the same
// bounded label the metric uses, so a log line and a metric series cannot
// disagree about why.
func recordAuthRejection(r *http.Request, reason, credentialType string) {
	secops.From(r.Context()).Emit(r.Context(), secops.Event{
		Type:    secops.EventAuthRejected,
		Control: controlForCredential(credentialType),
		Outcome: secops.OutcomeRejected,
		Evidence: map[string]string{
			"reason":          reason,
			"credential_type": credentialType,
		},
	})
}

func controlForCredential(credentialType string) string {
	if credentialType == "token" {
		return secops.ControlTokenVerification
	}
	return secops.ControlAPIKeyVerification
}

// recordCertMismatch records RFC 8705 binding refusing a token.
//
// The evidence is what this side of the exchange can prove: which
// certificate was actually presented, if any. The thumbprint the token
// demanded is inside the token, and the verifier does not hand it back on
// failure - deliberately, because every token rejection here answers with one
// opaque 401 and a verifier that returned the expected value would make this
// path an oracle for what a stolen token is bound to.
func recordCertMismatch(r *http.Request, binding jwt.Binding) {
	presented := "none"
	if binding.PeerCert != nil {
		presented = jwt.Thumbprint(binding.PeerCert)
	}
	secops.From(r.Context()).Emit(r.Context(), secops.Event{
		Type:    secops.EventCertMismatch,
		Control: secops.ControlCertificateBinding,
		Outcome: secops.OutcomeRejected,
		Evidence: map[string]string{
			"reason":                       "jwt_unbound_certificate",
			"presented_thumbprint":         presented,
			"client_certificate_presented": boolText(binding.PeerCert != nil),
		},
	})
}

// noteTokenPresentation hands a verified token to the replay filter.
//
// Only verified tokens: a token whose signature did not check out carries an
// attacker-chosen jti, and recording that would let anyone seed the filter
// with an id they could later pin on a real caller.
func noteTokenPresentation(r *http.Request, v *jwt.Verified) {
	rec := secops.From(r.Context())
	if rec == nil {
		return
	}
	peer := secops.PeerIdentity(presentedThumbprint(r), peerHost(r))
	rec.NoteTokenUse(r.Context(),
		secops.TokenID(v.Claims.ID, ""),
		peer,
		v.Claims.ExpiresAt,
		v.Claims.CertThumbprint != "",
	)
}

// presentedThumbprint is the client certificate's RFC 8705 thumbprint, or
// empty when the caller presented none.
func presentedThumbprint(r *http.Request) string {
	b := bindingFor(r)
	if b.PeerCert == nil {
		return ""
	}
	return jwt.Thumbprint(b.PeerCert)
}

// peerHost is the caller's address without its port, which is the only
// stable part: the port changes per connection.
func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
