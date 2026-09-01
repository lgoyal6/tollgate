package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/lgoyal6/tollgate/internal/config"
)

// listenerTLS builds the main listener's TLS configuration, or nil when the
// gateway is serving cleartext behind something that terminates for it.
//
// # Why VerifyClientCertIfGiven and not RequireAndVerifyClientCert
//
// The gateway is multi-tenant and most callers authenticate with an API key
// or an ordinary bearer token over one-way TLS. Requiring a client
// certificate from all of them would mean issuing one to every caller before
// any of this is useful, which is how mTLS ends up shelved.
//
// So: a client certificate is *optional*, and one that is presented is
// verified against the configured CA. That is the combination RFC 8705 needs.
// A token carrying cnf x5t#S256 is only spendable by the holder of the
// matching certificate's private key, and a token without cnf keeps working
// as it always did. The issuer decides which of its tokens are
// sender-constrained; the gateway honours that decision.
//
// The dangerous middle setting is RequestClientCert, which asks for a
// certificate and does not verify it. That would hand the binding check a
// certificate nobody vouched for, and since the check compares a thumbprint
// rather than a signature, an attacker could simply present the certificate
// the stolen token names and be believed. VerifyClientCertIfGiven is what
// makes the thumbprint comparison mean anything.
func listenerTLS(cfg config.Config) (*tls.Config, error) {
	if cfg.TLSCertFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}
	out := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// 1.2 floor rather than 1.3 only: a gateway that cannot be reached by
		// a caller on 1.2 is a gateway nobody uses, and 1.2 with these suites
		// is not the weak link in anything here.
		MinVersion: tls.VersionTLS12,
	}
	if cfg.ClientCAFile == "" {
		return out, nil
	}
	pem, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("reading client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		// AppendCertsFromPEM reports failure by returning false and nothing
		// else, so a typo'd path or a stray PEM block would otherwise become
		// an empty pool that verifies nothing and refuses every certificate.
		return nil, fmt.Errorf("client CA file %s contains no certificates", cfg.ClientCAFile)
	}
	out.ClientCAs = pool
	out.ClientAuth = tls.VerifyClientCertIfGiven
	return out, nil
}
