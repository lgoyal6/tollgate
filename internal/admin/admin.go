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
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
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

// Server is the management handler.
type Server struct {
	store  *store.Store
	usage  Usage
	token  string
	logger *slog.Logger

	console *template.Template
	mux     *http.ServeMux
}

// New builds the management handler. It returns nil when token is empty,
// which callers must treat as "management disabled" rather than an error:
// failing closed is the point.
func New(st *store.Store, usage Usage, token string, logger *slog.Logger) (*Server, error) {
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
	s := &Server{store: st, usage: usage, token: token, logger: logger, console: tmpl}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", s.handleConsole)
	mux.HandleFunc("GET /api/overview", s.jsonAuth(s.handleOverview))
	mux.HandleFunc("POST /api/tenants", s.jsonAuth(s.handleCreateTenant))
	mux.HandleFunc("PUT /api/tenants/{id}", s.jsonAuth(s.handleUpdateTenant))
	mux.HandleFunc("POST /api/tenants/{id}/keys", s.jsonAuth(s.handleIssueKey))
	mux.HandleFunc("POST /api/tenants/{id}/routes", s.jsonAuth(s.handleAddRoute))
	mux.HandleFunc("POST /api/keys/{id}/rotate", s.jsonAuth(s.handleRotateKey))
	mux.HandleFunc("DELETE /api/keys/{id}", s.jsonAuth(s.handleRevokeKey))
	mux.HandleFunc("DELETE /api/routes/{id}", s.jsonAuth(s.handleDeleteRoute))

	s.mux = mux
}

// Handler returns the management handler rooted at MountPath.
func (s *Server) Handler() http.Handler {
	return http.StripPrefix(MountPath, s.mux)
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
			if errors.Is(err, store.ErrNotFound) {
				code = http.StatusNotFound
			} else if code == 0 {
				code = http.StatusBadRequest
			}
			s.logger.Warn("admin request failed", "path", r.URL.Path, "method", r.Method, "err", err)
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if code == 0 {
			code = http.StatusOK
		}
		writeJSON(w, code, body)
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
func (s *Server) handleConsole(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
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
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Enabled   *bool   `json:"enabled"`
	Algorithm string  `json:"algorithm"`
	Rate      float64 `json:"rate"`
	Burst     int64   `json:"burst"`
	WindowMS  int64   `json:"window_ms"`
	Limit     int64   `json:"limit"`
}

func (t tenantRequest) spec(id string) store.TenantSpec {
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
		return nil, http.StatusBadRequest, fmt.Errorf("id is required")
	}
	if err := s.store.CreateTenant(r.Context(), req.spec(req.ID)); err != nil {
		return nil, http.StatusBadRequest, err
	}
	s.logger.Info("admin created tenant", "tenant", req.ID)
	return map[string]string{"status": "created", "tenant": req.ID}, http.StatusCreated, nil
}

func (s *Server) handleUpdateTenant(_ http.ResponseWriter, r *http.Request) (any, int, error) {
	id := r.PathValue("id")
	var req tenantRequest
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
		Scopes []string `json:"scopes"`
	}
	if err := decodeOptional(r, &req); err != nil {
		return nil, http.StatusBadRequest, err
	}
	gen, err := auth.Generate()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if err := s.store.InsertKey(r.Context(), gen.ID, tenant, gen.SecretHash, req.Scopes); err != nil {
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
	grace := time.Duration(req.GraceSeconds) * time.Second
	if grace <= 0 {
		grace = 24 * time.Hour
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
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("route id must be an integer: %w", err)
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
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parsing request body: %w", err)
	}
	return nil
}

// decodeOptional accepts an empty body, for endpoints where every field has a
// default (issue a key with no scopes, rotate with the default grace).
func decodeOptional(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("parsing request body: %w", err)
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
