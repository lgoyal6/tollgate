// Command tollgate-admin manages tenants, routes and API keys directly in
// Postgres. The gateway hot-reloads every change via LISTEN/NOTIFY, so
// nothing here requires a restart.
//
// Usage:
//
//	tollgate-admin create-tenant -id acme -name "Acme" -algo token_bucket -rate 100 -burst 200
//	tollgate-admin add-route     -tenant acme -prefix /api/ -upstream http://upstream-a:9000 [-strip] [-timeout 3s] [-retries 2] [-hedge] [-hedge-delay 50ms] [-scope read]
//	                             [-auth-header x-api-key -auth-env ANTHROPIC_API_KEY [-auth-prefix "Bearer "]]
//	tollgate-admin issue-key     -tenant acme -scopes read,write
//	tollgate-admin rotate-key    -key k1a2b3c4d5e6 -grace 24h
//	tollgate-admin revoke-key    -key k1a2b3c4d5e6
//	tollgate-admin list
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lgoyal6/tollgate/internal/auth"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tollgate-admin:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: tollgate-admin <create-tenant|add-route|issue-key|rotate-key|revoke-key|list> [flags]")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connecting to postgres: %w", err)
	}
	defer pool.Close()

	switch cmd := args[0]; cmd {
	case "create-tenant":
		return createTenant(ctx, pool, args[1:])
	case "add-route":
		return addRoute(ctx, pool, args[1:])
	case "issue-key":
		return issueKey(ctx, pool, args[1:])
	case "rotate-key":
		return rotateKey(ctx, pool, args[1:])
	case "revoke-key":
		return revokeKey(ctx, pool, args[1:])
	case "list":
		return list(ctx, pool)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func createTenant(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	fs := flag.NewFlagSet("create-tenant", flag.ExitOnError)
	id := fs.String("id", "", "tenant id (slug)")
	name := fs.String("name", "", "display name")
	algo := fs.String("algo", "token_bucket", "token_bucket | sliding_window")
	rate := fs.Float64("rate", 50, "token bucket: refill tokens/second")
	burst := fs.Int64("burst", 100, "token bucket: capacity")
	window := fs.Duration("window", time.Second, "sliding window size")
	limit := fs.Int64("limit", 50, "sliding window: max requests per window")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *name == "" {
		return fmt.Errorf("-id and -name are required")
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, name, rl_algorithm, rl_rate, rl_burst, rl_window_ms, rl_limit)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		*id, *name, *algo, *rate, *burst, window.Milliseconds(), *limit)
	if err != nil {
		return fmt.Errorf("inserting tenant: %w", err)
	}
	fmt.Printf("tenant %s created (%s)\n", *id, *algo)
	return nil
}

func addRoute(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	fs := flag.NewFlagSet("add-route", flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant id")
	prefix := fs.String("prefix", "", "path prefix, e.g. /api/")
	upstream := fs.String("upstream", "", "upstream base URL")
	strip := fs.Bool("strip", false, "strip the prefix before forwarding")
	timeout := fs.Duration("timeout", 5*time.Second, "per-attempt upstream timeout")
	retries := fs.Int("retries", 0, "max retries for idempotent methods")
	hedge := fs.Bool("hedge", false, "enable request hedging on this route")
	hedgeDelay := fs.Duration("hedge-delay", 50*time.Millisecond, "delay before firing the backup request")
	scope := fs.String("scope", "", "required key scope (empty = any)")
	authHeader := fs.String("auth-header", "", "upstream credential header to inject (e.g. x-api-key, Authorization)")
	authEnv := fs.String("auth-env", "", "gateway env var holding the upstream credential")
	authPrefix := fs.String("auth-prefix", "", "prefix for the injected value (e.g. \"Bearer \")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenant == "" || *prefix == "" || *upstream == "" {
		return fmt.Errorf("-tenant, -prefix and -upstream are required")
	}
	if (*authHeader == "") != (*authEnv == "") {
		return fmt.Errorf("-auth-header and -auth-env must be set together")
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO routes (tenant_id, path_prefix, upstream_url, strip_prefix, timeout_ms,
		                    retry_max, hedge_enabled, hedge_delay_ms, required_scope,
		                    upstream_auth_header, upstream_auth_env, upstream_auth_prefix)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11, $12)`,
		*tenant, *prefix, *upstream, *strip, timeout.Milliseconds(),
		*retries, *hedge, hedgeDelay.Milliseconds(), *scope,
		*authHeader, *authEnv, *authPrefix)
	if err != nil {
		return fmt.Errorf("inserting route: %w", err)
	}
	suffix := ""
	if *authHeader != "" {
		suffix = fmt.Sprintf(" (injects %s from $%s)", *authHeader, *authEnv)
	}
	fmt.Printf("route %s%s -> %s%s\n", *tenant, *prefix, *upstream, suffix)
	return nil
}

func issueKey(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	fs := flag.NewFlagSet("issue-key", flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant id")
	scopes := fs.String("scopes", "", "comma-separated scopes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenant == "" {
		return fmt.Errorf("-tenant is required")
	}
	key, err := insertKey(ctx, pool, *tenant, splitScopes(*scopes))
	if err != nil {
		return err
	}
	fmt.Printf("api key issued for %s — store it now, it is not recoverable:\n%s\n", *tenant, key)
	return nil
}

// rotateKey issues a fresh key with the old key's tenant and scopes, then
// puts the old key into a grace window so clients can switch without a gap.
func rotateKey(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	keyID := fs.String("key", "", "key id to rotate out")
	grace := fs.Duration("grace", 24*time.Hour, "how long the old key keeps working")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyID == "" {
		return fmt.Errorf("-key is required")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning rotation tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var tenant string
	var scopes []string
	err = tx.QueryRow(ctx, `
		UPDATE api_keys SET status = 'grace', grace_until = now() + $2, updated_at = now()
		WHERE id = $1 AND status = 'active'
		RETURNING tenant_id, scopes`, *keyID, *grace).Scan(&tenant, &scopes)
	if err != nil {
		return fmt.Errorf("marking key %s for grace (is it active?): %w", *keyID, err)
	}

	gen, err := auth.Generate()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO api_keys (id, tenant_id, secret_hash, scopes) VALUES ($1, $2, $3, $4)`,
		gen.ID, tenant, gen.SecretHash, scopes)
	if err != nil {
		return fmt.Errorf("inserting replacement key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing rotation: %w", err)
	}
	fmt.Printf("key %s enters %s grace window; replacement key:\n%s\n", *keyID, *grace, gen.Plaintext)
	return nil
}

func revokeKey(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	fs := flag.NewFlagSet("revoke-key", flag.ExitOnError)
	keyID := fs.String("key", "", "key id to revoke immediately")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyID == "" {
		return fmt.Errorf("-key is required")
	}
	tag, err := pool.Exec(ctx, `
		UPDATE api_keys SET status = 'revoked', grace_until = NULL, updated_at = now()
		WHERE id = $1 AND status <> 'revoked'`, *keyID)
	if err != nil {
		return fmt.Errorf("revoking key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("key %s not found or already revoked", *keyID)
	}
	fmt.Printf("key %s revoked\n", *keyID)
	return nil
}

func list(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `
		SELECT t.id, t.rl_algorithm, t.rl_rate, t.rl_burst, t.rl_window_ms, t.rl_limit,
		       count(DISTINCT r.id), count(DISTINCT k.id) FILTER (WHERE k.status = 'active')
		FROM tenants t
		LEFT JOIN routes r ON r.tenant_id = t.id
		LEFT JOIN api_keys k ON k.tenant_id = t.id
		GROUP BY t.id ORDER BY t.id`)
	if err != nil {
		return fmt.Errorf("listing tenants: %w", err)
	}
	defer rows.Close()
	fmt.Printf("%-12s %-15s %-20s %6s %6s\n", "TENANT", "ALGO", "POLICY", "ROUTES", "KEYS")
	for rows.Next() {
		var id, algo string
		var rate float64
		var burst, windowMs, limit, routes, keys int64
		if err := rows.Scan(&id, &algo, &rate, &burst, &windowMs, &limit, &routes, &keys); err != nil {
			return err
		}
		policy := fmt.Sprintf("%.0f/s burst %d", rate, burst)
		if algo == "sliding_window" {
			policy = fmt.Sprintf("%d per %dms", limit, windowMs)
		}
		fmt.Printf("%-12s %-15s %-20s %6d %6d\n", id, algo, policy, routes, keys)
	}
	return rows.Err()
}

func insertKey(ctx context.Context, pool *pgxpool.Pool, tenant string, scopes []string) (string, error) {
	gen, err := auth.Generate()
	if err != nil {
		return "", err
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO api_keys (id, tenant_id, secret_hash, scopes) VALUES ($1, $2, $3, $4)`,
		gen.ID, tenant, gen.SecretHash, scopes)
	if err != nil {
		return "", fmt.Errorf("inserting key: %w", err)
	}
	return gen.Plaintext, nil
}

func splitScopes(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
