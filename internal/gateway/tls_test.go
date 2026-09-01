package gateway

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lgoyal6/tollgate/internal/config"
	"github.com/lgoyal6/tollgate/internal/jwt"
	"github.com/lgoyal6/tollgate/internal/middleware"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/store"
)

// The end-to-end proof for RFC 8705: a token bound to a client certificate is
// useless to anyone who does not hold that certificate's private key, even
// when they hold the token itself and a perfectly valid certificate of their
// own.
//
// This exercises the real listenerTLS output rather than a tls.Config written
// for the test, because the interesting part is the interaction between
// VerifyClientCertIfGiven and the thumbprint comparison. The comparison is
// only worth anything because the handshake already established that somebody
// vouched for the certificate.

var b64raw = base64.RawURLEncoding

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, name string) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &ca{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue signs a leaf certificate. serverFor, when set, makes it a server
// certificate valid for that IP.
func (c *ca) issue(t *testing.T, name string, serverIP net.IP) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if serverIP != nil {
		tmpl.IPAddresses = []net.IP{serverIP}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

func writeKeyPair(t *testing.T, dir, name string, cert tls.Certificate) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: cert.Certificate[0],
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: der,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// A minimal issuer, so the test can mint a token bound to a certificate.
type idp struct {
	key *rsa.PrivateKey
	srv *httptest.Server
}

const (
	issuerName   = "https://issuer.test"
	issuerAud    = "https://api.tollgate.test"
	issuerTenant = "acme"
)

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &idp{key: key}
	i.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64raw.EncodeToString(key.N.Bytes()),
			"e": b64raw.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(i.srv.Close)
	return i
}

// mint issues an access token, bound to boundTo when it is not nil.
func (i *idp) mint(t *testing.T, boundTo *x509.Certificate) string {
	t.Helper()
	claims := map[string]any{
		"iss": issuerName, "sub": "user-1", "aud": issuerAud,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(), "scope": "read",
	}
	if boundTo != nil {
		claims["cnf"] = map[string]any{"x5t#S256": jwt.Thumbprint(boundTo)}
	}
	h, err := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := b64raw.EncodeToString(h) + "." + b64raw.EncodeToString(c)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64raw.EncodeToString(sig)
}

func (i *idp) tokenAuth(t *testing.T) *middleware.TokenAuth {
	t.Helper()
	src, err := jwt.NewKeySource(i.srv.URL, i.srv.Client(), time.Minute, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jwt.NewVerifier([]*jwt.Issuer{{
		Name: issuerName, Audience: issuerAud, TenantID: issuerTenant, Keys: src,
	}})
	if err != nil {
		t.Fatal(err)
	}
	// With a cache, so the binding check on a cache hit is exercised here too
	// and not only in the unit test.
	return &middleware.TokenAuth{Verifier: v, Cache: jwt.NewVerifiedCache(time.Minute, 64)}
}

func testChain(t *testing.T, tokens *middleware.TokenAuth) http.Handler {
	t.Helper()
	snap := store.SnapshotForTest(
		[]*store.Tenant{{ID: issuerTenant, Name: "Acme", Enabled: true}},
		[]*store.Route{{
			ID: 1, TenantID: issuerTenant, PathPrefix: "/api/", Timeout: time.Second,
			Upstream: &url.URL{Scheme: "http", Host: "upstream.invalid"},
		}},
		nil,
	)
	m := observability.NewMetrics()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	snapshots := func() *store.Snapshot { return snap }
	return middleware.Chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		middleware.Recover(logger), middleware.RequestID(),
		middleware.Auth(snapshots, m, tokens), middleware.Router(snapshots),
	)
}

// mtlsServer starts a TLS listener configured exactly as the gateway would
// configure it.
func mtlsServer(t *testing.T, handler http.Handler, clientCA *ca) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	authority := newCA(t, "tollgate test CA")
	serverCert, _ := authority.issue(t, "gateway", net.ParseIP("127.0.0.1"))
	certPath, keyPath := writeKeyPair(t, dir, "server", serverCert)

	cfg := config.Config{TLSCertFile: certPath, TLSKeyFile: keyPath}
	if clientCA != nil {
		cfg.ClientCAFile = filepath.Join(dir, "client-ca.pem")
		if err := os.WriteFile(cfg.ClientCAFile, clientCA.pem, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tlsCfg, err := listenerTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = tlsCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// clientWith returns an HTTP client that trusts the test server and presents
// cert, always, so an untrusted certificate is actually sent rather than
// silently withheld because the server did not name its CA.
func clientWith(srv *httptest.Server, cert *tls.Certificate) *http.Client {
	base := srv.Client().Transport.(*http.Transport).Clone()
	if cert != nil {
		base.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
	}
	return &http.Client{Transport: base}
}

func get(t *testing.T, c *http.Client, url, token string) (int, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url+"/api/thing", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func TestACertificateBoundTokenIsUselessWithoutTheCertificate(t *testing.T) {
	clientCA := newCA(t, "client CA")
	mine, mineLeaf := clientCA.issue(t, "rightful holder", nil)
	theirs, _ := clientCA.issue(t, "thief", nil)

	i := newIDP(t)
	srv := mtlsServer(t, testChain(t, i.tokenAuth(t)), clientCA)
	token := i.mint(t, mineLeaf)

	t.Run("the holder of the certificate", func(t *testing.T) {
		code, err := get(t, clientWith(srv, &mine), srv.URL, token)
		if err != nil || code != http.StatusOK {
			t.Fatalf("want 200, got %d (%v)", code, err)
		}
	})

	t.Run("the same token over one-way TLS", func(t *testing.T) {
		// This is the theft scenario: the token leaked into a log, and
		// whoever has it is trying to spend it.
		code, err := get(t, clientWith(srv, nil), srv.URL, token)
		if err != nil || code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d (%v)", code, err)
		}
	})

	t.Run("the same token with the thief's own valid certificate", func(t *testing.T) {
		// The interesting one. The thief is a legitimate client of this
		// gateway with a certificate the CA signed. It still does not help:
		// the token names a thumbprint that is not theirs.
		code, err := get(t, clientWith(srv, &theirs), srv.URL, token)
		if err != nil || code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d (%v)", code, err)
		}
	})

	t.Run("an unbound token still works without a certificate", func(t *testing.T) {
		// Binding is the issuer's decision, per token. Turning it on for one
		// issuer must not lock out everyone else.
		code, err := get(t, clientWith(srv, nil), srv.URL, i.mint(t, nil))
		if err != nil || code != http.StatusOK {
			t.Fatalf("want 200, got %d (%v)", code, err)
		}
	})
}

// The thumbprint comparison is only meaningful because the handshake already
// established that somebody vouched for the certificate. If the listener
// merely requested a certificate without verifying it, an attacker could
// present the very certificate a stolen token names and be believed.
func TestAnUnvouchedForCertificateNeverReachesTheBindingCheck(t *testing.T) {
	clientCA := newCA(t, "client CA")
	rogueCA := newCA(t, "rogue CA")
	rogue, rogueLeaf := rogueCA.issue(t, "rogue", nil)

	i := newIDP(t)
	srv := mtlsServer(t, testChain(t, i.tokenAuth(t)), clientCA)

	// A token naming the rogue certificate. If the rogue certificate were
	// accepted at the handshake, the thumbprint would match and this would
	// succeed.
	token := i.mint(t, rogueLeaf)
	if _, err := get(t, clientWith(srv, &rogue), srv.URL, token); err == nil {
		t.Fatal("a certificate from an unconfigured CA must fail the handshake")
	}
}

func TestListenerTLSConfiguration(t *testing.T) {
	dir := t.TempDir()
	authority := newCA(t, "ca")
	serverCert, _ := authority.issue(t, "gateway", net.ParseIP("127.0.0.1"))
	certPath, keyPath := writeKeyPair(t, dir, "server", serverCert)

	t.Run("no certificate means cleartext", func(t *testing.T) {
		cfg, err := listenerTLS(config.Config{})
		if err != nil || cfg != nil {
			t.Fatalf("want nil config, got %v (%v)", cfg, err)
		}
	})

	t.Run("a server certificate alone does not ask for client certificates", func(t *testing.T) {
		cfg, err := listenerTLS(config.Config{TLSCertFile: certPath, TLSKeyFile: keyPath})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ClientAuth != tls.NoClientCert {
			t.Fatalf("want NoClientCert, got %v", cfg.ClientAuth)
		}
	})

	t.Run("a client CA turns on optional verified client certificates", func(t *testing.T) {
		caPath := filepath.Join(dir, "ca.pem")
		if err := os.WriteFile(caPath, authority.pem, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := listenerTLS(config.Config{TLSCertFile: certPath, TLSKeyFile: keyPath, ClientCAFile: caPath})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
			// RequireAndVerify would lock out every caller who authenticates
			// with an API key; RequestClientCert would accept a certificate
			// nobody vouched for.
			t.Fatalf("want VerifyClientCertIfGiven, got %v", cfg.ClientAuth)
		}
		if cfg.ClientCAs == nil {
			t.Fatal("no CA pool installed")
		}
	})

	t.Run("a CA file with no certificates in it is an error", func(t *testing.T) {
		empty := filepath.Join(dir, "empty.pem")
		if err := os.WriteFile(empty, []byte("not a pem file\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// AppendCertsFromPEM reports failure by returning false and nothing
		// else, so without this check a typo would produce an empty pool that
		// refuses every certificate presented.
		if _, err := listenerTLS(config.Config{TLSCertFile: certPath, TLSKeyFile: keyPath, ClientCAFile: empty}); err == nil {
			t.Fatal("want an error")
		}
	})
}
