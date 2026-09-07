package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/reqctx"
	"github.com/lgoyal6/tollgate/internal/store"
)

// CurrentAccessChecker reads mutable credential and membership state from the
// shared authority at the point a protected action is about to run.
type CurrentAccessChecker func(context.Context, string, string, time.Time) (store.AccessState, error)

const currentAccessTimeout = 500 * time.Millisecond

// CurrentAuthorization closes the cross-replica revocation window left by the
// immutable config snapshot. It belongs after Concurrency so a request revoked
// while queued cannot proceed to budget accounting or the upstream.
func CurrentAuthorization(check CurrentAccessChecker, m *observability.Metrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := reqctx.TenantFrom(r.Context())
			key := reqctx.KeyFrom(r.Context())
			info := reqctx.InfoFrom(r.Context())
			if tenant == nil || key == nil {
				writeJSONError(w, info, http.StatusInternalServerError, "authorization check before auth")
				return
			}

			keyID := key.ID
			if strings.HasPrefix(keyID, "oidc:") {
				keyID = ""
			}
			checkCtx, cancel := context.WithTimeout(r.Context(), currentAccessTimeout)
			state, err := check(checkCtx, tenant.ID, keyID, time.Now())
			cancel()
			if err != nil {
				m.AuthFailures.WithLabelValues("current_check_unavailable").Inc()
				writeJSONError(w, info, http.StatusServiceUnavailable, "authorization state unavailable")
				return
			}
			if state != store.AccessAllowed {
				m.AuthFailures.WithLabelValues("current_" + string(state)).Inc()
				writeJSONError(w, info, http.StatusUnauthorized, "invalid credential")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
