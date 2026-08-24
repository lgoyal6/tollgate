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
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/store"
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
	// Both this CLI and the HTTP management API go through internal/store, so
	// key issuance and policy writes cannot drift between the two surfaces.
	st, err := store.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	switch cmd := args[0]; cmd {
	case "create-tenant":
		return createTenant(ctx, st, args[1:])
	case "add-route":
		return addRoute(ctx, st, args[1:])
	case "issue-key":
		return issueKey(ctx, st, args[1:])
	case "rotate-key":
		return rotateKey(ctx, st, args[1:])
	case "revoke-key":
		return revokeKey(ctx, st, args[1:])
	case "list":
		return list(ctx, st)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func createTenant(ctx context.Context, st *store.Store, args []string) error {
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
	spec := store.TenantSpec{
		ID: *id, Name: *name, Enabled: true, Algorithm: store.Algorithm(*algo),
		Rate: *rate, Burst: *burst, Window: *window, Limit: *limit,
	}
	if err := st.CreateTenant(ctx, spec); err != nil {
		return err
	}
	fmt.Printf("tenant %s created (%s)\n", *id, *algo)
	return nil
}

func addRoute(ctx context.Context, st *store.Store, args []string) error {
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
	spec := store.RouteSpec{
		TenantID: *tenant, PathPrefix: *prefix, Upstream: *upstream, StripPrefix: *strip,
		Timeout: *timeout, RetryMax: *retries, HedgeEnabled: *hedge, HedgeDelay: *hedgeDelay,
		RequiredScope: *scope, UpstreamAuthHeader: *authHeader, UpstreamAuthEnv: *authEnv,
		UpstreamAuthPrefix: *authPrefix,
	}
	if err := st.AddRoute(ctx, spec); err != nil {
		return err
	}
	suffix := ""
	if *authHeader != "" {
		suffix = fmt.Sprintf(" (injects %s from $%s)", *authHeader, *authEnv)
	}
	fmt.Printf("route %s%s -> %s%s\n", *tenant, *prefix, *upstream, suffix)
	return nil
}

func issueKey(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("issue-key", flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant id")
	scopes := fs.String("scopes", "", "comma-separated scopes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenant == "" {
		return fmt.Errorf("-tenant is required")
	}
	gen, err := auth.Generate()
	if err != nil {
		return err
	}
	if err := st.InsertKey(ctx, gen.ID, *tenant, gen.SecretHash, splitScopes(*scopes)); err != nil {
		return err
	}
	fmt.Printf("api key issued for %s - store it now, it is not recoverable:\n%s\n", *tenant, gen.Plaintext)
	return nil
}

// rotateKey issues a fresh key with the old key's tenant and scopes, then
// puts the old key into a grace window so clients can switch without a gap.
func rotateKey(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	keyID := fs.String("key", "", "key id to rotate out")
	grace := fs.Duration("grace", 24*time.Hour, "how long the old key keeps working")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyID == "" {
		return fmt.Errorf("-key is required")
	}
	gen, err := auth.Generate()
	if err != nil {
		return err
	}
	if _, err := st.RotateKey(ctx, *keyID, gen.ID, gen.SecretHash, *grace); err != nil {
		return err
	}
	fmt.Printf("key %s enters %s grace window; replacement key:\n%s\n", *keyID, *grace, gen.Plaintext)
	return nil
}

func revokeKey(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("revoke-key", flag.ExitOnError)
	keyID := fs.String("key", "", "key id to revoke immediately")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyID == "" {
		return fmt.Errorf("-key is required")
	}
	if err := st.RevokeKey(ctx, *keyID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("key %s not found or already revoked", *keyID)
		}
		return err
	}
	fmt.Printf("key %s revoked\n", *keyID)
	return nil
}

func list(ctx context.Context, st *store.Store) error {
	tenants, err := st.ListTenants(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("%-12s %-15s %-20s %6s %6s\n", "TENANT", "ALGO", "POLICY", "ROUTES", "KEYS")
	for _, t := range tenants {
		policy := fmt.Sprintf("%.0f/s burst %d", t.Rate, t.Burst)
		if t.Algorithm == store.AlgoSlidingWindow {
			policy = fmt.Sprintf("%d per %dms", t.Limit, t.Window.Milliseconds())
		}
		fmt.Printf("%-12s %-15s %-20s %6d %6d\n", t.ID, t.Algorithm, policy, t.Routes, t.ActiveKeys)
	}
	return nil
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
