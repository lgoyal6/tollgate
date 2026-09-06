package store

// The connection string is a credential. DATABASE_URL carries the database
// password, and the moment it is wrong is exactly the moment its text gets
// wrapped in an error, printed at boot and shipped to whatever collects the
// container's stderr - a different trust domain from the process environment
// it was meant to stay inside.
//
// pgx redacts the password itself. This pins that, because the property is
// invisible until it is gone: nothing about `fmt.Errorf("parsing DATABASE_URL:
// %w", err)` says whether the wrapped text is safe to print.

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestConnectionErrorsNeverCarryTheDatabasePassword(t *testing.T) {
	const password = "PASSWORD-THAT-MUST-NOT-BE-PRINTED"

	cases := map[string]string{
		// pgx redacts these two itself.
		"userinfo, port out of range": "postgres://svc:" + password + "@db.example:99999999/app",
		"keyword form, bad pool knob": "host=db.example user=svc password=" + password + " dbname=app pool_max_conns=abc",
		// It does not redact this one: libpq and pgx both accept the password
		// as a query parameter, and the parse error quoted the whole string.
		"query parameter, bad pool knob": "postgres://svc@db.example/app?password=" + password + "&pool_max_conns=abc",
		// Nothing here is recognisable as a password, so the string cannot be
		// shown at all.
		"not a connection string": "not a url at all, but with " + password + " in it",
		// And the connect path, which is a different error entirely.
		"nothing listening": "postgres://svc:" + password + "@127.0.0.1:1/app?connect_timeout=1",
	}

	for name, dsn := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			st, err := New(ctx, dsn)
			if err == nil {
				st.Close()
				t.Fatalf("expected %q to fail", name)
			}
			if strings.Contains(err.Error(), password) {
				t.Errorf("the error carries the database password: %v", err)
			}
		})
	}
}
