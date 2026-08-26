// Package config loads gateway configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds every tunable for the gateway process. All values come from
// environment variables so the same binary runs in compose and Kubernetes.
type Config struct {
	ListenAddr string // main proxy listener
	AdminAddr  string // health, metrics, pprof

	DatabaseURL string
	RedisAddr   string
	// RedisURL is the full redis://user:pass@host:port/db form. Managed Redis
	// always requires auth, and RedisAddr alone cannot carry a password, so a
	// hosted deploy sets this instead. It wins when both are present.
	RedisURL string

	// AdminToken gates the management API and console. Empty means the
	// management surface is not built at all: a gateway that was deployed
	// before it existed keeps behaving exactly as it did, and nobody can
	// issue keys over HTTP by accident. Setting it mounts the console on
	// both listeners (see internal/admin).
	AdminToken string

	// LimiterBackend selects "redis" (correct across replicas), "memory"
	// (deliberately naive per-replica limiter, kept to demonstrate why the
	// distributed one is needed), or "none" (rate limiting disabled entirely;
	// exists as the benchmark floor for measuring what limiting costs).
	LimiterBackend    string
	RateLimitFailOpen bool

	ReloadPollInterval time.Duration
	ReloadDebounce     time.Duration

	ShutdownTimeout time.Duration
	// DrainDelay is how long to keep serving after readiness flips to false,
	// giving load balancers time to remove this replica before Shutdown.
	DrainDelay time.Duration

	// HedgingEnabled is the global gate; a route must also opt in.
	HedgingEnabled bool
	// MaxBodyBuffer caps how much of a request body is buffered to make it
	// replayable for retries and hedging. Larger bodies are streamed once.
	MaxBodyBuffer int64

	TraceSampleRatio float64
	ServiceName      string
	Version          string

	UpstreamMaxIdlePerHost int

	AccessLogEnabled bool
	// AccessLogSample logs 1 in N requests (1 = every request).
	AccessLogSample int
	LogLevel        string
	// CORSOrigins is the explicit allow-list of browser origins. Empty means
	// no browser may call the gateway, which is the right default for a
	// service holding somebody else's provider key.
	CORSOrigins []string
}

// Load reads configuration from the environment, applying defaults and
// validating anything that must parse.
func Load() (Config, error) {
	cfg := Config{
		ListenAddr:     getenv("LISTEN_ADDR", defaultListenAddr()),
		AdminAddr:      getenv("ADMIN_ADDR", ":9090"),
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		RedisAddr:      getenv("REDIS_ADDR", "localhost:6379"),
		RedisURL:       os.Getenv("REDIS_URL"),
		AdminToken:     os.Getenv("ADMIN_TOKEN"),
		LimiterBackend: getenv("RATE_LIMITER", "redis"),
		ServiceName:    getenv("OTEL_SERVICE_NAME", "tollgate"),
		Version:        getenv("TOLLGATE_VERSION", "dev"),
		LogLevel:       getenv("LOG_LEVEL", "info"),
		CORSOrigins:    splitList(os.Getenv("CORS_ORIGINS")),
	}
	if cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.LimiterBackend != "redis" && cfg.LimiterBackend != "memory" && cfg.LimiterBackend != "none" {
		return Config{}, fmt.Errorf("RATE_LIMITER must be \"redis\", \"memory\" or \"none\", got %q", cfg.LimiterBackend)
	}

	var err error
	if cfg.RateLimitFailOpen, err = getBool("RATE_LIMIT_FAIL_OPEN", true); err != nil {
		return Config{}, err
	}
	if cfg.HedgingEnabled, err = getBool("HEDGING_ENABLED", false); err != nil {
		return Config{}, err
	}
	if cfg.AccessLogEnabled, err = getBool("ACCESS_LOG", true); err != nil {
		return Config{}, err
	}
	if cfg.ReloadPollInterval, err = getDuration("RELOAD_POLL_INTERVAL", 30*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.ReloadDebounce, err = getDuration("RELOAD_DEBOUNCE", 200*time.Millisecond); err != nil {
		return Config{}, err
	}
	if cfg.ShutdownTimeout, err = getDuration("SHUTDOWN_TIMEOUT", 30*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.DrainDelay, err = getDuration("DRAIN_DELAY", 0); err != nil {
		return Config{}, err
	}
	if cfg.MaxBodyBuffer, err = getInt64("MAX_BODY_BUFFER_BYTES", 1<<20); err != nil {
		return Config{}, err
	}
	if cfg.TraceSampleRatio, err = getFloat("TRACE_SAMPLE_RATIO", 0.1); err != nil {
		return Config{}, err
	}
	if cfg.UpstreamMaxIdlePerHost, err = getInt("UPSTREAM_MAX_IDLE_PER_HOST", 256); err != nil {
		return Config{}, err
	}
	if cfg.AccessLogSample, err = getInt("ACCESS_LOG_SAMPLE", 1); err != nil {
		return Config{}, err
	}
	if cfg.AccessLogSample < 1 {
		cfg.AccessLogSample = 1
	}
	return cfg, nil
}

// defaultListenAddr honours the PaaS convention of injecting the assigned
// port as $PORT. Render, Railway and Fly all do this, and a one-click deploy
// that ignores it binds the wrong port and never passes a health check.
// An explicit LISTEN_ADDR still wins.
func defaultListenAddr() string {
	if p := os.Getenv("PORT"); p != "" {
		return ":" + p
	}
	return ":8080"
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("parsing %s: %w", key, err)
	}
	return b, nil
}

func getDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", key, err)
	}
	return d, nil
}

func getInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", key, err)
	}
	return n, nil
}

func getInt64(key string, def int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", key, err)
	}
	return n, nil
}

func getFloat(key string, def float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", key, err)
	}
	return f, nil
}

// splitList parses a comma-separated env var, trimming blanks.
func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
