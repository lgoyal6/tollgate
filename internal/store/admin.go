package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This file holds the write side of the store. Both the tollgate-admin CLI
// and the HTTP management API call through here, so key issuance and policy
// changes cannot drift between the two surfaces. Every statement fires the
// tollgate_config NOTIFY trigger, so replicas hot-reload without a restart.

// ValidationError is a rejection phrased entirely in terms of the caller's
// own input and a documented constraint. It carries nothing about the
// database, so an API in front of this package may repeat its message back to
// a client verbatim; every other error this package returns may not, because
// what a driver puts in an error string is table names, constraint names,
// SQLSTATEs and the host it failed to reach.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// Invalid builds a ValidationError. Callers outside this package use it for
// the same purpose: to mark a message as safe to show a client.
func Invalid(format string, a ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, a...)}
}

// ConflictError marks a request that is valid in isolation but collides with
// state that already exists. Keeping this distinct from ValidationError lets
// HTTP callers tell a retryable create race from a malformed request without
// exposing a database constraint name.
type ConflictError struct{ Msg string }

func (e *ConflictError) Error() string { return e.Msg }

func Conflict(format string, a ...any) error {
	return &ConflictError{Msg: fmt.Sprintf(format, a...)}
}

// asClientError turns the two Postgres failures that are really caller
// mistakes into messages a caller can act on, so that hiding driver text does
// not also hide what went wrong. Anything else stays opaque on purpose.
func asClientError(err error, unique, _ string) error {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return err
	}
	switch pg.Code {
	case "23505": // unique_violation
		return Conflict("%s", unique)
	case "23503": // foreign_key_violation
		return ErrNotFound
	case "22021":
		// invalid byte sequence for encoding: a NUL inside a JSON string, say.
		// Postgres is right to refuse it and the caller is the one who sent it,
		// so this is a 400 rather than the gateway blaming itself.
		return &ValidationError{Msg: "a value contains a byte the database cannot store"}
	}
	return err
}

// TenantSpec is the full rate limit policy for one tenant. Updates replace
// the policy wholesale rather than patching single columns: the management UI
// always submits the current values back, and a full replace has no ordering
// or partial-update semantics to reason about.
type TenantSpec struct {
	ID      string
	Name    string
	Enabled bool

	Algorithm Algorithm
	Rate      float64
	Burst     int64
	Window    time.Duration
	Limit     int64
}

// Validate checks the fields the database's CHECK constraints would reject
// anyway, so the API can answer 400 instead of surfacing a Postgres error.
func (t TenantSpec) Validate() error {
	if t.ID == "" {
		return Invalid("tenant id is required")
	}
	if t.Name == "" {
		return Invalid("tenant name is required")
	}
	if strings.ContainsRune(t.ID, 0) || strings.ContainsRune(t.Name, 0) {
		return Invalid("tenant id and name cannot contain NUL")
	}
	if t.Algorithm != AlgoTokenBucket && t.Algorithm != AlgoSlidingWindow {
		return Invalid("algorithm must be %q or %q, got %q", AlgoTokenBucket, AlgoSlidingWindow, t.Algorithm)
	}
	if t.Rate <= 0 {
		return Invalid("rate must be > 0")
	}
	if t.Burst <= 0 {
		return Invalid("burst must be > 0")
	}
	if t.Window <= 0 {
		return Invalid("window must be > 0")
	}
	if t.Limit <= 0 {
		return Invalid("limit must be > 0")
	}
	return nil
}

// CreateTenant inserts a tenant and its rate limit policy.
func (s *Store) CreateTenant(ctx context.Context, spec TenantSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO tenants (id, name, enabled, rl_algorithm, rl_rate, rl_burst, rl_window_ms, rl_limit)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		spec.ID, spec.Name, spec.Enabled, string(spec.Algorithm),
		spec.Rate, spec.Burst, spec.Window.Milliseconds(), spec.Limit)
	if err != nil {
		return asClientError(fmt.Errorf("inserting tenant %s: %w", spec.ID, err),
			"a tenant with that id already exists", "no such tenant")
	}
	return nil
}

// UpdateTenant replaces a tenant's name, enabled flag and full rate limit
// policy. Flipping Enabled to false is the kill switch for a runaway client:
// it takes effect on every replica as soon as the reload lands, without
// revoking and reissuing keys.
func (s *Store) UpdateTenant(ctx context.Context, spec TenantSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE tenants SET name = $2, enabled = $3, rl_algorithm = $4, rl_rate = $5,
		       rl_burst = $6, rl_window_ms = $7, rl_limit = $8, updated_at = now()
		WHERE id = $1`,
		spec.ID, spec.Name, spec.Enabled, string(spec.Algorithm),
		spec.Rate, spec.Burst, spec.Window.Milliseconds(), spec.Limit)
	if err != nil {
		return fmt.Errorf("updating tenant %s: %w", spec.ID, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RouteSpec is one path prefix owned by a tenant, pointed at an upstream.
type RouteSpec struct {
	TenantID      string
	PathPrefix    string
	Upstream      string
	StripPrefix   bool
	Timeout       time.Duration
	RetryMax      int
	HedgeEnabled  bool
	HedgeDelay    time.Duration
	RequiredScope string

	UpstreamAuthHeader string
	UpstreamAuthEnv    string
	UpstreamAuthPrefix string
}

// Validate mirrors the routes table's constraints plus the invariant that
// credential injection needs both a header and an env var to mean anything.
func (r RouteSpec) Validate() error {
	if r.TenantID == "" || r.PathPrefix == "" || r.Upstream == "" {
		return Invalid("tenant, path prefix and upstream are required")
	}
	if r.PathPrefix[0] != '/' {
		return Invalid("path prefix must start with /")
	}
	// The upstream is where this gateway sends the credential it holds on
	// everybody's behalf, so it is checked here as well as at request time.
	// A URL this cannot parse is left to the snapshot loader to complain
	// about, which is where that error already belongs.
	if u, err := url.Parse(r.Upstream); err == nil {
		if reason, forbidden := ForbiddenUpstream(u.Host); forbidden {
			return Invalid("upstream is refused: %s", reason)
		}
	}
	for _, value := range []string{r.PathPrefix, r.Upstream, r.RequiredScope, r.UpstreamAuthHeader, r.UpstreamAuthEnv, r.UpstreamAuthPrefix} {
		if strings.ContainsRune(value, 0) {
			return Invalid("route fields cannot contain NUL")
		}
	}
	if r.Timeout <= 0 {
		return Invalid("timeout must be > 0")
	}
	if r.RetryMax < 0 || r.RetryMax > 5 {
		return Invalid("retries must be between 0 and 5")
	}
	if r.HedgeDelay <= 0 {
		return Invalid("hedge delay must be > 0")
	}
	if (r.UpstreamAuthHeader == "") != (r.UpstreamAuthEnv == "") {
		return Invalid("upstream auth header and env must be set together")
	}
	return nil
}

// AddRoute inserts a route. The upstream credential is named, never stored:
// only the env var's name lands in Postgres, the value stays in the gateway's
// environment.
func (s *Store) AddRoute(ctx context.Context, spec RouteSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO routes (tenant_id, path_prefix, upstream_url, strip_prefix, timeout_ms,
		                    retry_max, hedge_enabled, hedge_delay_ms, required_scope,
		                    upstream_auth_header, upstream_auth_env, upstream_auth_prefix)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11, $12)`,
		spec.TenantID, spec.PathPrefix, spec.Upstream, spec.StripPrefix, spec.Timeout.Milliseconds(),
		spec.RetryMax, spec.HedgeEnabled, spec.HedgeDelay.Milliseconds(), spec.RequiredScope,
		spec.UpstreamAuthHeader, spec.UpstreamAuthEnv, spec.UpstreamAuthPrefix)
	if err != nil {
		return asClientError(fmt.Errorf("inserting route %s%s: %w", spec.TenantID, spec.PathPrefix, err),
			"that route already exists", "no such tenant")
	}
	return nil
}

// DeleteRoute removes one route by id.
func (s *Store) DeleteRoute(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM routes WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting route %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// InsertKey persists an already-generated key. Callers generate the secret
// (package auth) and pass only its id and hash, so the plaintext never
// reaches this layer and the store never needs to import auth.
func (s *Store) InsertKey(ctx context.Context, id, tenantID string, secretHash []byte, scopes []string) error {
	if scopes == nil {
		scopes = []string{}
	}
	for _, scope := range scopes {
		if strings.ContainsRune(scope, 0) {
			return Invalid("scopes cannot contain NUL")
		}
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO api_keys (id, tenant_id, secret_hash, scopes) VALUES ($1, $2, $3, $4)`,
		id, tenantID, secretHash, scopes)
	if err != nil {
		return asClientError(fmt.Errorf("inserting key for %s: %w", tenantID, err),
			"a key with that id already exists", "no such tenant")
	}
	return nil
}

// RotateKey moves an active key into a grace window and inserts a
// replacement carrying the same tenant and scopes, in one transaction. The
// replacement's secret is generated by the caller. Returns the tenant the
// rotated key belonged to.
func (s *Store) RotateKey(ctx context.Context, oldID, newID string, newHash []byte, grace time.Duration) (string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("beginning rotation tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var tenant string
	var scopes []string
	err = tx.QueryRow(ctx, `
		UPDATE api_keys SET status = 'grace', grace_until = now() + $2, updated_at = now()
		WHERE id = $1 AND status = 'active'
		RETURNING tenant_id, scopes`, oldID, grace).Scan(&tenant, &scopes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Deliberately one sentence for both "no such key" and "that key
			// is already in grace or revoked": rotation must not be a way to
			// ask which key ids exist.
			return "", ErrNotFound
		}
		return "", fmt.Errorf("marking key %s for grace: %w", oldID, err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO api_keys (id, tenant_id, secret_hash, scopes) VALUES ($1, $2, $3, $4)`,
		newID, tenant, newHash, scopes); err != nil {
		return "", fmt.Errorf("inserting replacement key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("committing rotation: %w", err)
	}
	return tenant, nil
}

// RevokeKey kills a key immediately, with no grace window.
func (s *Store) RevokeKey(ctx context.Context, id string) error {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE api_keys SET status = 'revoked', grace_until = NULL, updated_at = now()
		WHERE id = $1 AND status <> 'revoked'`, id)
	if err != nil {
		return fmt.Errorf("revoking key %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
