// Package store owns everything Postgres: the schema model, snapshot loads,
// and hot reload via LISTEN/NOTIFY.
package store

import (
	"context"
	"errors"
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
		return nil, fmt.Errorf("parsing DATABASE_URL: %w", withoutPassword(err, databaseURL))
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

// withoutPassword strips the database password out of a connection-string
// error before it is returned, logged and shipped off the machine.
//
// pgx quotes the whole string back in its parse errors and redacts the
// password itself in two of the three forms it accepts - user:pass@ and the
// password= keyword - but not the third. A DATABASE_URL of the form
// postgres://user@host/db?password=... is echoed complete, and a parse error
// is exactly the moment a boot log gets pasted into a chat window.
//
// A password shorter than four characters is not substituted, because
// replacing every "p" in a sentence would mangle it; in that case the string
// is dropped instead.
func withoutPassword(err error, dsn string) error {
	const redacted = "xxxxx"
	msg := err.Error()
	passwords := passwordsIn(dsn)
	for _, pw := range passwords {
		if len(pw) >= 4 {
			msg = strings.ReplaceAll(msg, pw, redacted)
		}
	}
	for _, pw := range passwords {
		if pw != "" && strings.Contains(msg, pw) {
			return errors.New(unquotable)
		}
	}
	// pgx quotes the string back verbatim. That is only safe once it is known
	// to be one of the two forms a password can be found in; a string that is
	// neither is malformed, and a malformed string is where a password ends up
	// somewhere nothing knows to look.
	if strings.Contains(msg, dsn) && !isAKnownConnectionStringForm(dsn) {
		return errors.New(unquotable)
	}
	return errors.New(msg)
}

const unquotable = "the connection string could not be parsed, and is not repeated here: " +
	"it is not in a form this gateway can find a password in to redact"

// isAKnownConnectionStringForm reports whether dsn is a postgres URL or a
// keyword/value string, the two shapes passwordsIn knows how to read.
func isAKnownConnectionStringForm(dsn string) bool {
	if u, err := url.Parse(dsn); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		return true
	}
	fields := strings.Fields(dsn)
	if len(fields) == 0 {
		return false
	}
	for _, field := range fields {
		if !strings.Contains(field, "=") {
			return false
		}
	}
	return true
}

// passwordsIn finds the password in every form a Postgres connection string
// can carry one.
func passwordsIn(dsn string) []string {
	var out []string
	if u, err := url.Parse(dsn); err == nil {
		if u.User != nil {
			if pw, ok := u.User.Password(); ok {
				out = append(out, pw)
			}
		}
		if pw := u.Query().Get("password"); pw != "" {
			out = append(out, pw)
		}
	}
	for _, field := range strings.Fields(dsn) {
		if pw, ok := strings.CutPrefix(field, "password="); ok {
			out = append(out, pw)
		}
	}
	return out
}

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
		       upstream_auth_header, upstream_auth_env, upstream_auth_prefix,
		       fallback_upstream_url, fallback_auth_header, fallback_auth_env,
		       fallback_auth_prefix
		FROM routes`)
	if err != nil {
		return nil, fmt.Errorf("querying routes: %w", err)
	}
	for rows.Next() {
		var r Route
		var rawURL, rawFallbackURL string
		var timeoutMs, hedgeDelayMs int64
		if err := rows.Scan(&r.ID, &r.TenantID, &r.PathPrefix, &rawURL, &r.StripPrefix,
			&timeoutMs, &r.RetryMax, &r.HedgeEnabled, &hedgeDelayMs, &r.RequiredScope,
			&r.UpstreamAuthHeader, &r.UpstreamAuthEnv, &r.UpstreamAuthPrefix,
			&rawFallbackURL, &r.FallbackAuthHeader, &r.FallbackAuthEnv,
			&r.FallbackAuthPrefix); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning route: %w", err)
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("route %d has invalid upstream_url %q: %w", r.ID, rawURL, err)
		}
		r.Upstream = u
		if rawFallbackURL != "" {
			// A fallback the gateway cannot parse is refused at load rather
			// than at three in the morning, for the same reason the primary is.
			f, err := url.Parse(rawFallbackURL)
			if err != nil {
				rows.Close()
				return nil, fmt.Errorf("route %d has invalid fallback_upstream_url %q: %w", r.ID, rawFallbackURL, err)
			}
			r.FallbackUpstream = f
		}
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
