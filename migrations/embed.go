// Package migrations carries the schema as embedded files so a deploy that has
// no shell, no psql and no repository checkout can still create it. The one
// place that matters is a PaaS: Render, Fly and Railway provision Postgres and
// hand the container a URL, and nothing else in the box can apply a .sql file.
package migrations

import "embed"

// FS holds the numbered migrations in lexical order. seed.sql is deliberately
// excluded: it is demo data, not schema.
//
//go:embed *.sql
var FS embed.FS
