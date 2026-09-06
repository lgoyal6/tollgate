package config

// These tests pin the two behaviours a one-click PaaS deploy depends on: the
// assigned $PORT is honoured, and the management surface stays off unless a
// token is set.

import (
	"testing"
)

func TestListenAddrFollowsPaaSPort(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x/y")
	t.Setenv("PORT", "10000")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":10000" {
		t.Fatalf("ListenAddr = %q, want \":10000\" from $PORT", cfg.ListenAddr)
	}
}

func TestExplicitListenAddrBeatsPort(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x/y")
	t.Setenv("PORT", "10000")
	t.Setenv("LISTEN_ADDR", ":9999")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":9999" {
		t.Fatalf("ListenAddr = %q, want the explicit \":9999\"", cfg.ListenAddr)
	}
}

func TestDefaultListenAddrWithoutPort(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x/y")
	t.Setenv("PORT", "") // hermetic: an ambient $PORT must not decide this test

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("ListenAddr = %q, want \":8080\"", cfg.ListenAddr)
	}
}

func TestAdminTokenDefaultsToEmpty(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x/y")
	t.Setenv("ADMIN_TOKEN", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AdminToken != "" {
		t.Fatalf("AdminToken = %q, want empty so the management surface stays off by default", cfg.AdminToken)
	}
}

func TestRedisURLIsReadWhenSet(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x/y")
	t.Setenv("REDIS_URL", "redis://default:secret@redis.internal:6379")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RedisURL != "redis://default:secret@redis.internal:6379" {
		t.Fatalf("RedisURL = %q, want the value from the environment", cfg.RedisURL)
	}
	// REDIS_ADDR keeps its default so a local run is unaffected.
	if cfg.RedisAddr != "localhost:6379" {
		t.Fatalf("RedisAddr = %q, want the unchanged default", cfg.RedisAddr)
	}
}

// The abuse limits have to be on by default. A gateway that only bounds a
// request when somebody remembered to set seven environment variables is a
// gateway with no bounds, so the defaults are pinned here rather than left to
// whatever a deploy happens to export.
func TestAbuseLimitsAreOnByDefault(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x/y")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checks := []struct {
		name string
		got  int64
	}{
		{"MaxRequestBytes", cfg.Limits.MaxRequestBytes},
		{"MaxDecompressedBytes", cfg.Limits.MaxDecompressedBytes},
		{"MaxResponseBytes", cfg.Limits.MaxResponseBytes},
		{"MaxInFlightPerTenant", int64(cfg.Limits.MaxInFlightPerTenant)},
		{"MaxQueuePerTenant", int64(cfg.Limits.MaxQueuePerTenant)},
		{"QueueWait", int64(cfg.Limits.QueueWait)},
		{"MaxRequestDuration", int64(cfg.Limits.MaxRequestDuration)},
	}
	for _, c := range checks {
		if c.got <= 0 {
			t.Errorf("%s = %d: every abuse limit must default to enforced", c.name, c.got)
		}
	}
	// The decompressed cap being below the wire cap would make compression a
	// way to send a SMALLER request, which is backwards.
	if cfg.Limits.MaxDecompressedBytes < cfg.Limits.MaxRequestBytes {
		t.Errorf("MaxDecompressedBytes (%d) below MaxRequestBytes (%d)",
			cfg.Limits.MaxDecompressedBytes, cfg.Limits.MaxRequestBytes)
	}
}

// Zero is the documented way to turn a bound off, and it has to keep working:
// it is the only escape hatch for a deployment these defaults break.
func TestAbuseLimitsCanBeDisabledExplicitly(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x/y")
	t.Setenv("MAX_REQUEST_BYTES", "0")
	t.Setenv("MAX_INFLIGHT_PER_TENANT", "0")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Limits.MaxRequestBytes != 0 || cfg.Limits.MaxInFlightPerTenant != 0 {
		t.Errorf("explicit 0 did not disable: request=%d inflight=%d",
			cfg.Limits.MaxRequestBytes, cfg.Limits.MaxInFlightPerTenant)
	}
}

func TestAbuseLimitsRejectGarbage(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x/y")
	t.Setenv("MAX_REQUEST_BYTES", "eight megabytes")

	if _, err := Load(); err == nil {
		t.Fatal("Load accepted an unparseable MAX_REQUEST_BYTES")
	}
}
