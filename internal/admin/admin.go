// Package admin serves the gateway's management surface: a small JSON API for
// tenants, routes and keys, plus the single-page console that drives it.
//
// The surface is opt-in. Without ADMIN_TOKEN set the gateway builds no
// handler at all, which is exactly the behaviour deployments had before this
// package existed. With it set, the same handler is mounted on both the admin
// listener and, under a reserved prefix, the tenant listener, because a
// one-container PaaS deploy only gets one public port and the whole point of
// this package is that issuing a teammate a key should not require shell
// access to the container.
package admin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lgoyal6/tollgate/internal/auth"
	"github.com/lgoyal6/tollgate/internal/store"
)

// MountPath is the reserved prefix the console and API live under on the
// tenant-facing listener. It is matched before route lookup, so a tenant
// cannot shadow it with a route of their own.
const MountPath = "/_admin"

//go:embed console.html
var assets embed.FS

// Usage reports per-tenant traffic counters for this process.
type Usage interface {
	TenantUsage() map[string]TenantCounters
}

// TenantCounters is what one tenant has done, as counted by this replica.
type TenantCounters struct {
	Requests  float64 `json:"requests"`
	Admitted  float64 `json:"admitted"`
	Limited   float64 `json:"limited"`
	ServerErr float64 `json:"server_errors"`
}

// Reloader is the config snapshot this replica serves requests from. The
// management API refreshes it after every write, because a key lives in two
// places: the row it was written to, and the snapshot the request path
// actually authenticates against. Without this the watcher would still pick
// the change up, but only after its debounce or its poll, and a revocation
// that answers 200 while the credential still works is not a revocation.
type Reloader interface {
	Load(context.Context) error
}

// Server is the management handler.
type Server struct {
	store    *store.Store
	usage    Usage
	token    string
	logger   *slog.Logger
	reloader Reloader

	console *template.Template
	mux     *http.ServeMux
}

// New builds the management handler. It returns nil when token is empty,
// which callers must treat as "management disabled" rather than an error:
// failing closed is the point.
//
// reloader may be nil, in which case writes bind whenever the watcher next
// reloads; the gateway always passes one.
func New(st *store.Store, usage Usage, token string, logger *slog.Logger, reloader Reloader) (*Server, error) {
	if token == "" {
		return nil, nil
	}
	if len(token) < 16 {
		return nil, fmt.Errorf("ADMIN_TOKEN must be at least 16 characters (got %d); it is the only thing standing in front of key issuance", len(token))
	}
	tmpl, err := template.ParseFS(assets, "console.html")
	if err != nil {
		return nil, fmt.Errorf("parsing console template: %w", err)
	}
	s := &Server{store: st, usage: usage, token: token, logger: logger, reloader: reloader, console: tmpl}
	s.routes()
	return s, nil
}

// operation is one JSON endpoint of the management API.
//
// A table rather than a run of mux.HandleFunc calls because openapi.json is
// the published contract for this API, and a contract that is written down
// separately from the code drifts from it. With the surface enumerable, the
// test in contract_test.go can compare the two in both directions: an
// endpoint added here without a spec entry fails, and so does a spec entry
// with no endpoint behind it.
type operation struct {
	Method string
	Path   string // ServeMux pattern, {id} for a path parameter
	// Exactly one of these is set. api handlers answer JSON from behind the
	// admin token; raw handlers answer for themselves and are public.
	api func(http.ResponseWriter, *http.Request) (any, int, error)
	raw http.HandlerFunc
}

func (s *Server) apiOperations() []operation {
	return []operation{
		{Method: "GET", Path: "/api/overview", api: s.handleOverview},
		{Method: "POST", Path: "/api/tenants", api: s.handleCreateTenant},
		{Method: "PUT", Path: "/api/tenants/{id}", api: s.handleUpdateTenant},
		{Method: "POST", Path: "/api/tenants/{id}/keys", api: s.handleIssueKey},
		{Method: "POST", Path: "/api/tenants/{id}/routes", api: s.handleAddRoute},
		{Method: "POST", Path: "/api/keys/{id}/rotate", api: s.handleRotateKey},
		{Method: "DELETE", Path: "/api/keys/{id}", api: s.handleRevokeKey},
		{Method: "DELETE", Path: "/api/routes/{id}", api: s.handleDeleteRoute},
	}
}

// operations is every pattern this server serves, and the only place any of
// them is registered. The console is in here too rather than being wired
// straight onto the mux, because a handler that does not pass through this
// table is a handler openapi.json is never compared against, and an
// undocumented endpoint on this surface is one that issues keys.
func (s *Server) operations() []operation {
	return append([]operation{
		// {$} rather than / so the console matches the mount root only. As a
		// bare "/" it would also answer for every unmatched path, which is
		// how an unknown endpoint came to reply in text/plain.
		{Method: "GET", Path: "/{$}", raw: s.handleConsole},
	}, s.apiOperations()...)
}

func (s *Server) routes() {
	mux := http.NewServeMux()
	allowed := map[string][]string{}
	for _, op := range s.operations() {
		pattern := op.Method + " " + op.Path
		if op.raw != nil {
			mux.HandleFunc(pattern, op.raw)
		} else {
			mux.HandleFunc(pattern, s.jsonAuth(op.api))
		}
		allowed[op.Path] = append(allowed[op.Path], op.Method)
	}
	// The one literal, and not an endpoint: it is what answers when no
	// endpoint matched. net/http's mux would otherwise write those two
	// replies itself, in text/plain with no `error` field, which is a
	// response shape this API's contract does not contain.
	mux.Handle("/", s.unmatched(allowed))
	s.mux = mux
}

// unmatched answers for every path and method no operation claims: 405 with
// an Allow header when the path exists under another method, 404 otherwise,
// both in the same JSON envelope as everything else here.
func (s *Server) unmatched(allowed map[string][]string) http.Handler {
	// A second mux, registered by path with no method, purely to answer "is
	// this path one of ours?" - which is what separates a 405 from a 404.
	paths := http.NewServeMux()
	for pattern, methods := range allowed {
		sort.Strings(methods)
		allow := strings.Join(methods, ", ")
		paths.HandleFunc(pattern, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Allow", allow)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := paths.Handler(r); pattern != "" {
			paths.ServeHTTP(w, r)
			return
		}
		s.notFound(w)
	})
}

// MountOn returns a handler that answers for everything under MountPath with
// surface, and hands every other request to next.
//
// Deliberately not an http.ServeMux. net/http's router answers a path that is
// not in canonical form with a 307 to the cleaned path, before any handler
// runs, so a POST to /_admin/api/tenants//keys is told to re-send its body to
// a path with the tenant parameter collapsed out of it. That is a status this
// API does not declare, with an empty body and no content type, and on a
// surface that issues credentials it is worse than a refusal. Two prefixes do
// not need a router.
func MountOn(surface, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p := r.URL.Path; {
		case p == MountPath:
			http.Redirect(w, r, MountPath+"/", http.StatusMovedPermanently)
		case strings.HasPrefix(p, MountPath+"/"):
			surface.ServeHTTP(w, r)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// Handler returns the management handler rooted at MountPath.
func (s *Server) Handler() http.Handler {
	return http.StripPrefix(MountPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// net/http's mux answers a path that needs cleaning - the empty path
		// parameter in /api/tenants//keys, say - with a 307 to the cleaned
		// path: no body, no content type, and a status this API does not
		// declare. On a management API that is worse than a refusal, because
		// a client that follows it re-sends its body to a path where a
		// parameter has silently collapsed away. So the surface refuses.
		if needsCleaning(r.URL.EscapedPath()) {
			s.notFound(w)
			return
		}
		s.mux.ServeHTTP(w, r)
	}))
}

// needsCleaning reports whether net/http's mux would rewrite this path, using
// the same rule it does: path.Clean, with a trailing slash preserved.
func needsCleaning(p string) bool {
	if p == "" {
		return true
	}
	cleaned := path.Clean(p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return p != cleaned
}

// notFound is the one 404 body this surface has. It is deliberately the same
// sentence whatever the path was, so that failing to find an endpoint cannot
// be used to map the ones that exist.
func (s *Server) notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such endpoint"})
}

// jsonAuth wraps a handler with bearer token authentication. The comparison is
// constant time so a wrong token leaks nothing through timing.
func (s *Server) jsonAuth(h func(http.ResponseWriter, *http.Request) (any, int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tollgate"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing admin token"})
			return
		}
		body, code, err := h(w, r)
		if err != nil {
			code, msg := clientError(err, code)
			// The full error, driver text and all, goes to the operator's log
			// and nowhere else.
			s.logger.Warn("admin request failed", "path", r.URL.Path, "method", r.Method,
				"status", code, "err", err)
			writeJSON(w, code, map[string]string{"error": msg})
			return
		}
		if code == 0 {
			code = http.StatusOK
		}
		// Refresh before answering, not after, so the response is only sent
		// once this replica is serving the change. Every write here is a
		// human-scale event, so a full snapshot load per call is cheap next
		// to the alternative: a revoke that returns 200 while the credential
		// still works for another debounce interval.
		if r.Method != http.MethodGet {
			s.refresh(r.Context())
		}
		writeJSON(w, code, body)
	}
}

// clientError decides what a caller is told about a failure.
//
// The rule is an allow-list, not a deny-list: a message reaches the client
// only if something deliberately marked it as being about the client's own
// input. Everything else becomes a fixed sentence, because the alternative -
// relaying err.Error() - relayed the table and constraint names out of
// Postgres foreign key violations, "no rows in result set" out of pgx, and
// the server's own FATAL text when the database went away.
func clientError(err error, code int) (int, string) {
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound, "not found"
	}
	var conflict *store.ConflictError
	if errors.As(err, &conflict) {
		return http.StatusConflict, conflict.Error()
	}
	var invalid *store.ValidationError
	if errors.As(err, &invalid) {
		if code == 0 || code >= 500 {
			code = http.StatusBadRequest
		}
		return code, invalid.Error()
	}
	// Nothing marked this one as being about the caller's input, so it is the
	// gateway's problem and not theirs; answering 4xx would be a lie about
	// whose fault it is, and every path here can fail on the database.
	return http.StatusInternalServerError, "the request could not be completed"
}

// refresh reloads this replica's config snapshot after a write.
//
// A failure is logged rather than returned: the row is already committed, so
// answering with an error would be a lie about what happened, and the
// watcher's LISTEN/NOTIFY path converges anyway. Other replicas always take
// that path, so the guarantee this buys is per process, not cluster-wide.
func (s *Server) refresh(ctx context.Context) {
	if s.reloader == nil {
		return
	}
	if err := s.reloader.Load(ctx); err != nil {
		s.logger.Warn("config snapshot reload after management write failed; change binds when the watcher next reloads", "err", err)
	}
}

func (s *Server) authorized(r *http.Request) bool {
	raw := r.Header.Get("Authorization")
	presented, ok := strings.CutPrefix(raw, "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.token)) == 1
}

// handleConsole serves the single-page console. It carries no secrets: the
// operator pastes the admin token into the page, and the page holds it in
// memory only, so the token is never written to disk or into a URL.
func (s *Server) handleConsole(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.console.Execute(w, map[string]string{"Mount": MountPath}); err != nil {
		s.logger.Error("rendering console", "err", err)
	}
}

// overview is everything the console needs in one round trip.
type overview struct {
	Tenants []tenantView              `json:"tenants"`
	Routes  []store.RouteInfo         `json:"routes"`
	Keys    []store.KeyInfo           `json:"keys"`
	Usage   map[string]TenantCounters `json:"usage"`
}

type tenantView struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Enabled    bool    `json:"enabled"`
	Algorithm  string  `json:"algorithm"`
	Rate       float64 `json:"rate"`
	Burst      int64   `json:"burst"`
	WindowMS   int64   `json:"window_ms"`
	Limit      int64   `json:"limit"`
	Routes     int     `json:"routes"`
	ActiveKeys int     `json:"active_keys"`
}

func (s *Server) handleOverview(_ http.ResponseWriter, r *http.Request) (any, int, error) {
	ctx := r.Context()
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	routes, err := s.store.ListRoutes(ctx, "")
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	keys, err := s.store.ListKeys(ctx, "")
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	views := make([]tenantView, 0, len(tenants))
	for _, t := range tenants {
		views = append(views, tenantView{
			ID: t.ID, Name: t.Name, Enabled: t.Enabled,
			Algorithm: string(t.Algorithm), Rate: t.Rate, Burst: t.Burst,
			WindowMS: t.Window.Milliseconds(), Limit: t.Limit,
			Routes: t.Routes, ActiveKeys: t.ActiveKeys,
		})
	}
	out := overview{Tenants: views, Routes: routes, Keys: keys, Usage: map[string]TenantCounters{}}
	if s.usage != nil {
		out.Usage = s.usage.TenantUsage()
	}
	return out, http.StatusOK, nil
}

type tenantRequest struct {
	ID string `json:"id"`
	tenantPolicyRequest
}

type tenantPolicyRequest struct {
	Name      string  `json:"name"`
	Enabled   *bool   `json:"enabled"`
	Algorithm string  `json:"algorithm"`
	Rate      float64 `json:"rate"`
	Burst     int64   `json:"burst"`
	WindowMS  int64   `json:"window_ms"`
	Limit     int64   `json:"limit"`
}

func (t tenantPolicyRequest) spec(id string) store.TenantSpec {
	enabled := true
	if t.Enabled != nil {
		enabled = *t.Enabled
	}
	name := t.Name
	if name == "" {
		name = id
	}
	algo := store.Algorithm(t.Algorithm)
	if algo == "" {
		algo = store.AlgoTokenBucket
	}
	spec := store.TenantSpec{
		ID: id, Name: name, Enabled: enabled, Algorithm: algo,
		Rate: t.Rate, Burst: t.Burst, Limit: t.Limit,
		Window: time.Duration(t.WindowMS) * time.Millisecond,
	}
	// Each algorithm reads only its own pair of knobs, but both pairs are
	// stored and constrained to be positive, so fill the unused pair with the
	// schema defaults rather than making the caller send fields it ignores.
	if spec.Rate == 0 {
		spec.Rate = 50
	}
	if spec.Burst == 0 {
		spec.Burst = 100
	}
	if spec.Limit == 0 {
		spec.Limit = 50
	}
	if spec.Window == 0 {
		spec.Window = time.Second
	}
	return spec
}

func (s *Server) handleCreateTenant(_ http.ResponseWriter, r *http.Request) (any, int, error) {
	var req tenantRequest
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if req.ID == "" {
		return nil, http.StatusBadRequest, store.Invalid("id is required")
	}
	if err := s.store.CreateTenant(r.Context(), req.spec(req.ID)); err != nil {
		return nil, http.StatusBadRequest, err
	}
	s.logger.Info("admin created tenant", "tenant", req.ID)
	return map[string]string{"status": "created", "tenant": req.ID}, http.StatusCreated, nil
}

func (s *Server) handleUpdateTenant(_ http.ResponseWriter, r *http.Request) (any, int, error) {
	id := r.PathValue("id")
	var req tenantPolicyRequest
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if err := s.store.UpdateTenant(r.Context(), req.spec(id)); err != nil {
		return nil, 0, err
	}
	s.logger.Info("admin updated tenant policy", "tenant", id)
	return map[string]string{"status": "updated", "tenant": id}, http.StatusOK, nil
}

func (s *Server) handleIssueKey(_ http.ResponseWriter, r *http.Request) (any, int, error) {
	tenant := r.PathValue("id")
	var req struct {
		Scopes []strictString `json:"scopes"`
	}
	if err := decodeOptional(r, &req); err != nil {
		return nil, http.StatusBadRequest, err
	}
	scopes := make([]string, len(req.Scopes))
	for i, scope := range req.Scopes {
		scopes[i] = string(scope)
	}
	gen, err := auth.Generate()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if err := s.store.InsertKey(r.Context(), gen.ID, tenant, gen.SecretHash, scopes); err != nil {
		return nil, http.StatusBadRequest, err
	}
	s.logger.Info("admin issued key", "tenant", tenant, "key", gen.ID)
	// The plaintext is returned exactly once and never stored.
	return map[string]any{
		"key_id": gen.ID,
		"key":    gen.Plaintext,
		"tenant": tenant,
		"note":   "shown once, not recoverable",
	}, http.StatusCreated, nil
}

// strictString prevents encoding/json's surprising null-to-empty-string
// coercion inside arrays. The OpenAPI contract says scopes contain strings;
// accepting [null] as [""] makes generated negative tests pass through.
type strictString string

func (s *strictString) UnmarshalJSON(raw []byte) error {
	if string(raw) == "null" {
		return errors.New("must be a string")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*s = strictString(value)
	return nil
}

func (s *Server) handleAddRoute(_ http.ResponseWriter, r *http.Request) (any, int, error) {
	tenant := r.PathValue("id")
	var req struct {
		PathPrefix    string `json:"path_prefix"`
		Upstream      string `json:"upstream"`
		StripPrefix   bool   `json:"strip_prefix"`
		TimeoutMS     int64  `json:"timeout_ms"`
		RetryMax      int    `json:"retry_max"`
		RequiredScope string `json:"required_scope"`
		AuthHeader    string `json:"auth_header"`
		AuthEnv       string `json:"auth_env"`
		AuthPrefix    string `json:"auth_prefix"`
	}
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, err
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout == 0 {
		timeout = 120 * time.Second // LLM upstreams stream for a long time
	}
	spec := store.RouteSpec{
		TenantID: tenant, PathPrefix: req.PathPrefix, Upstream: req.Upstream,
		StripPrefix: req.StripPrefix, Timeout: timeout, RetryMax: req.RetryMax,
		HedgeDelay: 50 * time.Millisecond, RequiredScope: req.RequiredScope,
		UpstreamAuthHeader: req.AuthHeader, UpstreamAuthEnv: req.AuthEnv,
		UpstreamAuthPrefix: req.AuthPrefix,
	}
	if err := s.store.AddRoute(r.Context(), spec); err != nil {
		return nil, http.StatusBadRequest, err
	}
	s.logger.Info("admin added route", "tenant", tenant, "prefix", req.PathPrefix, "upstream", req.Upstream)
	return map[string]string{"status": "created", "tenant": tenant, "prefix": req.PathPrefix}, http.StatusCreated, nil
}

func (s *Server) handleRotateKey(_ http.ResponseWriter, r *http.Request) (any, int, error) {
	keyID := r.PathValue("id")
	var req struct {
		GraceSeconds int64 `json:"grace_seconds"`
	}
	if err := decodeOptional(r, &req); err != nil {
		return nil, http.StatusBadRequest, err
	}
	var grace time.Duration
	switch {
	case req.GraceSeconds <= 0:
		grace = 24 * time.Hour
	case req.GraceSeconds > 9223372036:
		return nil, http.StatusBadRequest, store.Invalid("grace seconds exceed the supported duration")
	default:
		grace = time.Duration(req.GraceSeconds) * time.Second
	}
	gen, err := auth.Generate()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	tenant, err := s.store.RotateKey(r.Context(), keyID, gen.ID, gen.SecretHash, grace)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	s.logger.Info("admin rotated key", "old", keyID, "new", gen.ID, "tenant", tenant, "grace", grace)
	return map[string]any{
		"key_id":      gen.ID,
		"key":         gen.Plaintext,
		"tenant":      tenant,
		"replaced":    keyID,
		"grace_until": time.Now().Add(grace).UTC().Format(time.RFC3339),
		"note":        "shown once, not recoverable",
	}, http.StatusCreated, nil
}

func (s *Server) handleRevokeKey(_ http.ResponseWriter, r *http.Request) (any, int, error) {
	keyID := r.PathValue("id")
	if err := s.store.RevokeKey(r.Context(), keyID); err != nil {
		return nil, 0, err
	}
	s.logger.Info("admin revoked key", "key", keyID)
	return map[string]string{"status": "revoked", "key_id": keyID}, http.StatusOK, nil
}

func (s *Server) handleDeleteRoute(_ http.ResponseWriter, r *http.Request) (any, int, error) {
	// The parse error itself is not repeated: strconv names its own function
	// and echoes the input back, and neither is anything the caller needs.
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, http.StatusBadRequest, store.Invalid("route id must be an integer")
	}
	if err := s.store.DeleteRoute(r.Context(), id); err != nil {
		return nil, 0, err
	}
	s.logger.Info("admin deleted route", "route", id)
	return map[string]any{"status": "deleted", "route_id": id}, http.StatusOK, nil
}

// maxBody caps management request bodies. Nothing here legitimately needs
// more than a few hundred bytes.
const maxBody = 64 << 10

func decode(r *http.Request, dst any) error {
	return decodeJSON(r, dst, false)
}

// decodeOptional accepts an empty body, for endpoints where every field has a
// default (issue a key with no scopes, rotate with the default grace).
func decodeOptional(r *http.Request, dst any) error {
	return decodeJSON(r, dst, true)
}

func decodeJSON(r *http.Request, dst any, optional bool) error {
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBody))
	if err != nil {
		return store.Invalid("parsing request body: %v", err)
	}
	hadBytes := len(raw) > 0
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 && optional && !hadBytes {
		return nil
	}
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return store.Invalid("request body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return store.Invalid("parsing request body: %v", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return store.Invalid("request body must contain one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}
