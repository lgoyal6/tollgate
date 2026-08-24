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
