package store

import (
	"context"
	"fmt"
	"time"
)

// This file holds the write side of the store. Both the tollgate-admin CLI
// and the HTTP management API call through here, so key issuance and policy
// changes cannot drift between the two surfaces. Every statement fires the
// tollgate_config NOTIFY trigger, so replicas hot-reload without a restart.

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
		return fmt.Errorf("tenant id is required")
	}
	if t.Name == "" {
		return fmt.Errorf("tenant name is required")
	}
	if t.Algorithm != AlgoTokenBucket && t.Algorithm != AlgoSlidingWindow {
		return fmt.Errorf("algorithm must be %q or %q, got %q", AlgoTokenBucket, AlgoSlidingWindow, t.Algorithm)
	}
	if t.Rate <= 0 {
		return fmt.Errorf("rate must be > 0")
	}
	if t.Burst <= 0 {
		return fmt.Errorf("burst must be > 0")
	}
	if t.Window <= 0 {
		return fmt.Errorf("window must be > 0")
	}
	if t.Limit <= 0 {
		return fmt.Errorf("limit must be > 0")
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
		return fmt.Errorf("inserting tenant %s: %w", spec.ID, err)
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
		return fmt.Errorf("tenant, path prefix and upstream are required")
	}
	if r.PathPrefix[0] != '/' {
		return fmt.Errorf("path prefix must start with /")
	}
	if r.Timeout <= 0 {
		return fmt.Errorf("timeout must be > 0")
	}
	if r.RetryMax < 0 || r.RetryMax > 5 {
		return fmt.Errorf("retries must be between 0 and 5")
	}
	if r.HedgeDelay <= 0 {
		return fmt.Errorf("hedge delay must be > 0")
	}
	if (r.UpstreamAuthHeader == "") != (r.UpstreamAuthEnv == "") {
		return fmt.Errorf("upstream auth header and env must be set together")
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
		return fmt.Errorf("inserting route %s%s: %w", spec.TenantID, spec.PathPrefix, err)
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
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO api_keys (id, tenant_id, secret_hash, scopes) VALUES ($1, $2, $3, $4)`,
		id, tenantID, secretHash, scopes)
	if err != nil {
		return fmt.Errorf("inserting key for %s: %w", tenantID, err)
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
		return "", fmt.Errorf("marking key %s for grace (is it active?): %w", oldID, err)
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
