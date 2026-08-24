package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned by write helpers when the row they meant to change
// does not exist, so callers can answer 404 instead of guessing from a zero
// rows-affected count.
var ErrNotFound = errors.New("not found")

// TenantOverview is one row of the management view: policy plus how many
// routes and live keys hang off it.
type TenantOverview struct {
	TenantSpec
	Routes     int `json:"routes"`
	ActiveKeys int `json:"active_keys"`
}

// ListTenants returns every tenant with its policy and child counts.
func (s *Store) ListTenants(ctx context.Context) ([]TenantOverview, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT t.id, t.name, t.enabled, t.rl_algorithm, t.rl_rate, t.rl_burst,
		       t.rl_window_ms, t.rl_limit,
		       count(DISTINCT r.id),
		       count(DISTINCT k.id) FILTER (WHERE k.status IN ('active', 'grace'))
		FROM tenants t
		LEFT JOIN routes r ON r.tenant_id = t.id
		LEFT JOIN api_keys k ON k.tenant_id = t.id
		GROUP BY t.id ORDER BY t.id`)
	if err != nil {
		return nil, fmt.Errorf("listing tenants: %w", err)
	}
	defer rows.Close()

	var out []TenantOverview
	for rows.Next() {
		var o TenantOverview
		var algo string
		var windowMs int64
		if err := rows.Scan(&o.ID, &o.Name, &o.Enabled, &algo, &o.Rate, &o.Burst,
			&windowMs, &o.Limit, &o.Routes, &o.ActiveKeys); err != nil {
			return nil, fmt.Errorf("scanning tenant: %w", err)
		}
		o.Algorithm = Algorithm(algo)
		o.Window = time.Duration(windowMs) * time.Millisecond
		out = append(out, o)
	}
	return out, rows.Err()
}

// KeyInfo is a key as the management surface may show it: identity and
// lifecycle only. The secret hash is never returned.
type KeyInfo struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Scopes     []string   `json:"scopes"`
	Status     KeyStatus  `json:"status"`
	GraceUntil *time.Time `json:"grace_until,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// ListKeys returns every key, newest first. A tenant id narrows it to one
// tenant; empty returns all of them.
func (s *Store) ListKeys(ctx context.Context, tenantID string) ([]KeyInfo, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, tenant_id, scopes, status, grace_until, created_at
		FROM api_keys
		WHERE ($1 = '' OR tenant_id = $1)
		ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing keys: %w", err)
	}
	defer rows.Close()

	out := []KeyInfo{}
	for rows.Next() {
		var k KeyInfo
		var status string
		if err := rows.Scan(&k.ID, &k.TenantID, &k.Scopes, &status, &k.GraceUntil, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning key: %w", err)
		}
		k.Status = KeyStatus(status)
		out = append(out, k)
	}
	return out, rows.Err()
}

// RouteInfo is a route as the management surface shows it. CredentialFrom
// names the environment variable the gateway injects from, which is safe to
// display: it is a name, not a secret.
type RouteInfo struct {
	ID             int64  `json:"id"`
	TenantID       string `json:"tenant_id"`
	PathPrefix     string `json:"path_prefix"`
	Upstream       string `json:"upstream"`
	StripPrefix    bool   `json:"strip_prefix"`
	TimeoutMS      int64  `json:"timeout_ms"`
	RetryMax       int    `json:"retry_max"`
	RequiredScope  string `json:"required_scope,omitempty"`
	CredentialFrom string `json:"credential_from,omitempty"`
	CredentialSet  bool   `json:"credential_set"`
}

// ListRoutes returns every route, or just one tenant's when tenantID is set.
func (s *Store) ListRoutes(ctx context.Context, tenantID string) ([]RouteInfo, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, tenant_id, path_prefix, upstream_url, strip_prefix, timeout_ms,
		       retry_max, coalesce(required_scope, ''), upstream_auth_env, upstream_auth_header
		FROM routes
		WHERE ($1 = '' OR tenant_id = $1)
		ORDER BY tenant_id, length(path_prefix) DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing routes: %w", err)
	}
	defer rows.Close()

	out := []RouteInfo{}
	for rows.Next() {
		var r RouteInfo
		var authEnv, authHeader string
		if err := rows.Scan(&r.ID, &r.TenantID, &r.PathPrefix, &r.Upstream, &r.StripPrefix,
			&r.TimeoutMS, &r.RetryMax, &r.RequiredScope, &authEnv, &authHeader); err != nil {
			return nil, fmt.Errorf("scanning route: %w", err)
		}
		r.CredentialFrom = authEnv
		r.CredentialSet = authEnv != "" && authHeader != ""
		out = append(out, r)
	}
	return out, rows.Err()
}
