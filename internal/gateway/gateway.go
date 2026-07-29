// Package gateway wires config, store, limiter, proxy and middleware into a
// running process: one listener for tenant traffic, one admin listener for
// health, metrics and pprof, and a shutdown sequence that drains in-flight
// requests before exiting.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"

	"github.com/lgoyal6/tollgate/internal/config"
	"github.com/lgoyal6/tollgate/internal/middleware"
	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/proxy"
	"github.com/lgoyal6/tollgate/internal/ratelimit"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

// Gateway owns the process lifecycle.
type Gateway struct {
	cfg     config.Config
	logger  *slog.Logger
	metrics *observability.Metrics

	store   *store.Store
	watcher *store.Watcher
	limiter ratelimit.Limiter
	redis   *redis.Client

	ready atomic.Bool
}

// New builds but does not start the gateway.
func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*Gateway, error) {
	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("initializing store: %w", err)
	}

	g := &Gateway{
		cfg:     cfg,
		logger:  logger,
		metrics: observability.NewMetrics(),
		store:   st,
		watcher: store.NewWatcher(st, logger, cfg.ReloadPollInterval, cfg.ReloadDebounce),
	}

	switch cfg.LimiterBackend {
	case "memory":
		logger.Warn("using NAIVE in-memory rate limiter: limits are per replica, not global")
		g.limiter = ratelimit.NewMemoryLimiter()
	case "none":
		logger.Warn("rate limiting DISABLED: every request is admitted; benchmark floor only")
	default:
		g.redis = redis.NewClient(&redis.Options{
			Addr:         cfg.RedisAddr,
			DialTimeout:  2 * time.Second,
			ReadTimeout:  500 * time.Millisecond,
			WriteTimeout: 500 * time.Millisecond,
			PoolSize:     64,
			MinIdleConns: 8,
		})
		if err := g.redis.Ping(ctx).Err(); err != nil {
			st.Close()
			return nil, fmt.Errorf("pinging redis at %s: %w", cfg.RedisAddr, err)
		}
		g.limiter = ratelimit.NewRedisLimiter(g.redis)
	}
	return g, nil
}

// handler assembles the full middleware chain around the proxy.
func (g *Gateway) handler() http.Handler {
	breakers := resilience.NewBreakerGroup(resilience.DefaultBreakerConfig())
	breakers.OnStateChange = func(host string, from, to resilience.State) {
		g.metrics.BreakerState.WithLabelValues(host).Set(float64(to))
		g.metrics.BreakerTransitions.WithLabelValues(host, to.String()).Inc()
		g.logger.Warn("circuit breaker transition", "upstream", host, "from", from.String(), "to", to.String())
	}

	px := proxy.New(proxy.Options{
		Breakers:       breakers,
		HedgingEnabled: g.cfg.HedgingEnabled,
		MaxBodyBuffer:  g.cfg.MaxBodyBuffer,
		MaxIdlePerHost: g.cfg.UpstreamMaxIdlePerHost,
		Logger:         g.logger,
		Metrics:        g.metrics,
	})

	snapshots := g.watcher.Snapshot
	mws := []middleware.Middleware{
		middleware.Recover(g.logger),
		middleware.RequestID(),
		middleware.AccessLog(g.logger, g.cfg.AccessLogEnabled, g.cfg.AccessLogSample),
		middleware.Metrics(g.metrics),
		middleware.Tracing(g.cfg.ServiceName),
		middleware.Auth(snapshots, g.metrics),
		middleware.Router(snapshots),
	}
	// LimiterBackend "none" leaves g.limiter nil: the RateLimit middleware is
	// not in the chain at all, which is the honest floor when measuring what
	// admission control costs.
	if g.limiter != nil {
		mws = append(mws, middleware.RateLimit(g.limiter, g.cfg.RateLimitFailOpen, g.metrics, g.logger))
	}
	return middleware.Chain(px, mws...)
}

// adminHandler serves health, metrics and pprof on the admin port so none of
// it is reachable through the tenant-facing listener.
func (g *Gateway) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !g.ready.Load() || g.watcher.Snapshot() == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(g.metrics.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// Run blocks until SIGINT/SIGTERM, then drains and exits.
func (g *Gateway) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := observability.SetupTracing(ctx, g.cfg.ServiceName, g.cfg.Version, g.cfg.TraceSampleRatio, g.logger)
	if err != nil {
		return fmt.Errorf("setting up tracing: %w", err)
	}

	// First config load is synchronous: the gateway never serves a request
	// without tenants, keys and routes.
	loadCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = g.watcher.Load(loadCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("initial config load: %w", err)
	}

	watchCtx, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()
	go g.watcher.Run(watchCtx)
	go g.mirrorReloadCounters(watchCtx)

	mainSrv := &http.Server{
		Addr:              g.cfg.ListenAddr,
		Handler:           g.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	adminSrv := &http.Server{
		Addr:              g.cfg.AdminAddr,
		Handler:           g.adminHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	limiterName := "none"
	if g.limiter != nil {
		limiterName = g.limiter.Name()
	}
	errCh := make(chan error, 2)
	go func() {
		g.logger.Info("gateway listening", "addr", g.cfg.ListenAddr, "limiter", limiterName)
		if err := mainSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("main listener: %w", err)
		}
	}()
	go func() {
		g.logger.Info("admin listening", "addr", g.cfg.AdminAddr)
		if err := adminSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("admin listener: %w", err)
		}
	}()

	g.ready.Store(true)

	select {
	case <-ctx.Done():
		g.logger.Info("shutdown signal received; draining")
	case err := <-errCh:
		return err
	}

	// Drain sequence: flip readiness so load balancers stop sending traffic,
	// wait for endpoint propagation, then let in-flight requests finish.
	g.ready.Store(false)
	if g.cfg.DrainDelay > 0 {
		g.logger.Info("waiting for load balancer to notice", "delay", g.cfg.DrainDelay)
		time.Sleep(g.cfg.DrainDelay)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), g.cfg.ShutdownTimeout)
	defer cancel()
	if err := mainSrv.Shutdown(shutdownCtx); err != nil {
		g.logger.Error("main listener drain incomplete", "error", err)
	} else {
		g.logger.Info("in-flight requests drained")
	}
	_ = adminSrv.Shutdown(shutdownCtx)

	cancelWatch()
	if err := shutdownTracing(context.Background()); err != nil {
		g.logger.Warn("tracer shutdown", "error", err)
	}
	if g.redis != nil {
		_ = g.redis.Close()
	}
	g.store.Close()
	g.logger.Info("gateway stopped cleanly")
	return nil
}

// mirrorReloadCounters bridges the watcher's atomic counters into Prometheus.
func (g *Gateway) mirrorReloadCounters(ctx context.Context) {
	var seenOK, seenFail int64
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if ok := g.watcher.Reloads.Load(); ok > seenOK {
				g.metrics.ConfigReloads.Add(float64(ok - seenOK))
				seenOK = ok
			}
			if fail := g.watcher.ReloadFailures.Load(); fail > seenFail {
				g.metrics.ConfigReloadFailures.Add(float64(fail - seenFail))
				seenFail = fail
			}
		}
	}
}
