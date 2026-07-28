// Package reqctx carries per-request state through the middleware chain.
// Info is installed once at the top of the chain and mutated as layers learn
// things (tenant after auth, upstream after routing), so outer layers like
// access logging and RED metrics can read the final values after the inner
// handler returns.
package reqctx

import (
	"context"

	"github.com/lgoyal6/tollgate/internal/store"
)

// Info accumulates facts about one request as it moves down the chain.
type Info struct {
	RequestID     string
	TraceID       string
	TenantID      string
	KeyID         string
	RoutePrefix   string
	Upstream      string
	Status        int
	BytesOut      int64
	RateLimited   bool
	KeyDeprecated bool
	Attempts      int
	Hedged        bool
	Error         string
}

// RouteLabel returns a bounded-cardinality route identifier for metrics.
func (i *Info) RouteLabel() string {
	if i.RoutePrefix == "" {
		return "unmatched"
	}
	return i.RoutePrefix
}

// TenantLabel returns the tenant for metrics, or "unauthenticated".
func (i *Info) TenantLabel() string {
	if i.TenantID == "" {
		return "unauthenticated"
	}
	return i.TenantID
}

type ctxKey int

const (
	infoKey ctxKey = iota
	tenantKey
	routeKey
	keyKey
)

func WithInfo(ctx context.Context, info *Info) context.Context {
	return context.WithValue(ctx, infoKey, info)
}

// InfoFrom never returns nil so downstream code can write without checking;
// a detached Info simply goes nowhere.
func InfoFrom(ctx context.Context) *Info {
	if info, ok := ctx.Value(infoKey).(*Info); ok {
		return info
	}
	return &Info{}
}

func WithTenant(ctx context.Context, t *store.Tenant) context.Context {
	return context.WithValue(ctx, tenantKey, t)
}

func TenantFrom(ctx context.Context) *store.Tenant {
	t, _ := ctx.Value(tenantKey).(*store.Tenant)
	return t
}

func WithRoute(ctx context.Context, r *store.Route) context.Context {
	return context.WithValue(ctx, routeKey, r)
}

func RouteFrom(ctx context.Context) *store.Route {
	r, _ := ctx.Value(routeKey).(*store.Route)
	return r
}

func WithKey(ctx context.Context, k *store.APIKey) context.Context {
	return context.WithValue(ctx, keyKey, k)
}

func KeyFrom(ctx context.Context) *store.APIKey {
	k, _ := ctx.Value(keyKey).(*store.APIKey)
	return k
}
