package store

import (
	"net/url"
	"time"
)

// Algorithm names a rate limiting strategy. Stored per tenant in Postgres.
type Algorithm string

const (
	AlgoTokenBucket   Algorithm = "token_bucket"
	AlgoSlidingWindow Algorithm = "sliding_window"
)

// Tenant is one customer of the gateway. Rate limit policy lives here so it
// can be changed at runtime and hot-reloaded.
type Tenant struct {
	ID      string
	Name    string
	Enabled bool

	RLAlgorithm Algorithm
	// Token bucket: RLRate tokens/second refill, RLBurst capacity.
	RLRate  float64
	RLBurst int64
	// Sliding window: RLLimit requests per RLWindow.
	RLWindow time.Duration
	RLLimit  int64
}

// Route maps a path prefix owned by a tenant to an upstream.
type Route struct {
	ID            int64
	TenantID      string
	PathPrefix    string
	Upstream      *url.URL
	StripPrefix   bool
	Timeout       time.Duration
	RetryMax      int
	HedgeEnabled  bool
	HedgeDelay    time.Duration
	RequiredScope string

	// Upstream credential injection: when Header and Env are set, the proxy
	// sends `<Header>: <Prefix><value of $Env>` upstream. The tenant's own
	// gateway key is always stripped first, so callers never need — or see —
	// the real provider credential (e.g. a team's shared Anthropic key).
	UpstreamAuthHeader string
	UpstreamAuthEnv    string
	UpstreamAuthPrefix string
}

// InjectsCredential reports whether this route is configured to attach an
// upstream credential.
func (r *Route) InjectsCredential() bool {
	return r.UpstreamAuthHeader != "" && r.UpstreamAuthEnv != ""
}

// KeyStatus is the lifecycle state of an API key.
type KeyStatus string

const (
	KeyActive KeyStatus = "active"
	// KeyGrace means the key was rotated out but still validates until
	// GraceUntil, so clients can roll over without an outage.
	KeyGrace   KeyStatus = "grace"
	KeyRevoked KeyStatus = "revoked"
)

// APIKey is the stored form of a credential. Only the SHA-256 of the secret
// is persisted; the plaintext is shown once at issue time.
type APIKey struct {
	ID         string
	TenantID   string
	SecretHash []byte
	Scopes     []string
	Status     KeyStatus
	GraceUntil *time.Time
}
