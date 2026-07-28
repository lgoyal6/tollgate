// Package store owns everything Postgres: the schema model, snapshot loads,
// and hot reload via LISTEN/NOTIFY.
package store

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var txReadOnly = pgx.TxOptions{AccessMode: pgx.ReadOnly}

// Store wraps the pgx pool.
type Store struct {
	Pool *pgxpool.Pool
}

func New(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing DATABASE_URL: %w", err)
	}
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() { s.Pool.Close() }

// Snapshot is an immutable view of the routing/auth/rate-limit config.
// The gateway swaps whole snapshots atomically; request handlers never
// touch the database.
type Snapshot struct {
	LoadedAt time.Time
	tenants  map[string]*Tenant
	keys     map[string]*APIKey
	// routes per tenant, sorted longest prefix first so MatchRoute can take
	// the first hit.
	routes map[string][]*Route
}

func (s *Snapshot) Tenant(id string) (*Tenant, bool) {
	t, ok := s.tenants[id]
	return t, ok
}

func (s *Snapshot) Key(id string) (*APIKey, bool) {
	k, ok := s.keys[id]
	return k, ok
}

// MatchRoute returns the longest-prefix route for the tenant and path.
func (s *Snapshot) MatchRoute(tenantID, path string) (*Route, bool) {
	for _, r := range s.routes[tenantID] {
		if strings.HasPrefix(path, r.PathPrefix) {
			return r, true
		}
	}
	return nil, false
}

// Counts reports sizes for logging after a reload.
func (s *Snapshot) Counts() (tenants, routes, keys int) {
	for _, rs := range s.routes {
		routes += len(rs)
	}
	return len(s.tenants), routes, len(s.keys)
}

// SnapshotForTest builds a Snapshot in memory. Tests only; production
// snapshots always come from LoadSnapshot.
func SnapshotForTest(tenants []*Tenant, routes []*Route, keys []*APIKey) *Snapshot {
	snap := &Snapshot{
		LoadedAt: time.Now(),
		tenants:  make(map[string]*Tenant),
		keys:     make(map[string]*APIKey),
		routes:   make(map[string][]*Route),
	}
	for _, t := range tenants {
		snap.tenants[t.ID] = t
	}
	for _, k := range keys {
		snap.keys[k.ID] = k
	}
	for _, r := range routes {
		snap.routes[r.TenantID] = append(snap.routes[r.TenantID], r)
	}
	for _, rs := range snap.routes {
		sort.Slice(rs, func(i, j int) bool { return len(rs[i].PathPrefix) > len(rs[j].PathPrefix) })
	}
	return snap
}

// LoadSnapshot reads the full config in one consistent transaction.
func (s *Store) LoadSnapshot(ctx context.Context) (*Snapshot, error) {
	tx, err := s.Pool.BeginTx(ctx, txReadOnly)
	if err != nil {
		return nil, fmt.Errorf("beginning snapshot tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // read-only rollback

	snap := &Snapshot{
		LoadedAt: time.Now(),
		tenants:  make(map[string]*Tenant),
		keys:     make(map[string]*APIKey),
		routes:   make(map[string][]*Route),
	}

	rows, err := tx.Query(ctx, `
		SELECT id, name, enabled, rl_algorithm, rl_rate, rl_burst, rl_window_ms, rl_limit
		FROM tenants`)
	if err != nil {
		return nil, fmt.Errorf("querying tenants: %w", err)
	}
	for rows.Next() {
		var t Tenant
		var windowMs int64
		if err := rows.Scan(&t.ID, &t.Name, &t.Enabled, &t.RLAlgorithm, &t.RLRate, &t.RLBurst, &windowMs, &t.RLLimit); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning tenant: %w", err)
		}
		t.RLWindow = time.Duration(windowMs) * time.Millisecond
		snap.tenants[t.ID] = &t
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterating tenants: %w", rows.Err())
	}

	rows, err = tx.Query(ctx, `
		SELECT id, tenant_id, path_prefix, upstream_url, strip_prefix, timeout_ms,
		       retry_max, hedge_enabled, hedge_delay_ms, COALESCE(required_scope, ''),
		       upstream_auth_header, upstream_auth_env, upstream_auth_prefix
		FROM routes`)
	if err != nil {
		return nil, fmt.Errorf("querying routes: %w", err)
	}
	for rows.Next() {
		var r Route
		var rawURL string
		var timeoutMs, hedgeDelayMs int64
		if err := rows.Scan(&r.ID, &r.TenantID, &r.PathPrefix, &rawURL, &r.StripPrefix,
			&timeoutMs, &r.RetryMax, &r.HedgeEnabled, &hedgeDelayMs, &r.RequiredScope,
			&r.UpstreamAuthHeader, &r.UpstreamAuthEnv, &r.UpstreamAuthPrefix); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning route: %w", err)
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("route %d has invalid upstream_url %q: %w", r.ID, rawURL, err)
		}
		r.Upstream = u
		r.Timeout = time.Duration(timeoutMs) * time.Millisecond
		r.HedgeDelay = time.Duration(hedgeDelayMs) * time.Millisecond
		snap.routes[r.TenantID] = append(snap.routes[r.TenantID], &r)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterating routes: %w", rows.Err())
	}
	for _, rs := range snap.routes {
		sort.Slice(rs, func(i, j int) bool { return len(rs[i].PathPrefix) > len(rs[j].PathPrefix) })
	}

	rows, err = tx.Query(ctx, `
		SELECT id, tenant_id, secret_hash, scopes, status, grace_until
		FROM api_keys WHERE status <> 'revoked'`)
	if err != nil {
		return nil, fmt.Errorf("querying api_keys: %w", err)
	}
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.TenantID, &k.SecretHash, &k.Scopes, &k.Status, &k.GraceUntil); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning api key: %w", err)
		}
		snap.keys[k.ID] = &k
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, fmt.Errorf("iterating api_keys: %w", rows.Err())
	}

	return snap, nil
}
