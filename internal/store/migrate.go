package store

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/lgoyal6/tollgate/migrations"
)

// Each applied migration is recorded so a second run is a no-op. A PaaS
// restarts containers freely, so this must be safe to run on every boot.
// Migrate applies every numbered migration that has not run yet.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("creating schema_migrations: %w", err)
	}

	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)

	applied := 0
	for _, name := range names {
		// seed.sql is demo data and is applied by hand, never by this.
		if !strings.HasPrefix(name, "0") {
			continue
		}
		var done bool
		if err := s.Pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name,
		).Scan(&done); err != nil {
			return fmt.Errorf("checking %s: %w", name, err)
		}
		if done {
			continue
		}
		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			return err
		}
		// One transaction per migration: a failure leaves the schema where it
		// was rather than half-applied.
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("applying %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("recording %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing %s: %w", name, err)
		}
		fmt.Println("applied", name)
		applied++
	}
	if applied == 0 {
		fmt.Println("schema already up to date")
	}
	return nil
}
