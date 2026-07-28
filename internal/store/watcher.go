package store

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// notifyChannel is raised by Postgres triggers on any change to tenants,
// routes, or api_keys (see migrations/001_init.sql).
const notifyChannel = "tollgate_config"

// Watcher keeps an always-current Snapshot without restarting the gateway.
// It LISTENs on a dedicated connection for change notifications, debounces
// them (one UPDATE statement can fire many), and reloads. A periodic poll
// backstops missed notifications (e.g. after a connection drop).
type Watcher struct {
	store        *Store
	logger       *slog.Logger
	pollInterval time.Duration
	debounce     time.Duration

	current atomic.Pointer[Snapshot]

	// Reloads and ReloadFailures are exported as Prometheus counters by the
	// gateway; the watcher just counts.
	Reloads        atomic.Int64
	ReloadFailures atomic.Int64
}

func NewWatcher(s *Store, logger *slog.Logger, pollInterval, debounce time.Duration) *Watcher {
	return &Watcher{
		store:        s,
		logger:       logger,
		pollInterval: pollInterval,
		debounce:     debounce,
	}
}

// Snapshot returns the current config. Nil until the first successful load.
func (w *Watcher) Snapshot() *Snapshot { return w.current.Load() }

// Load performs one synchronous reload. Used at startup so the gateway never
// serves without config, and by the notify/poll loops afterwards.
func (w *Watcher) Load(ctx context.Context) error {
	snap, err := w.store.LoadSnapshot(ctx)
	if err != nil {
		w.ReloadFailures.Add(1)
		return err
	}
	w.current.Store(snap)
	w.Reloads.Add(1)
	tenants, routes, keys := snap.Counts()
	w.logger.Info("config reloaded", "tenants", tenants, "routes", routes, "api_keys", keys)
	return nil
}

// Run blocks until ctx is done, keeping the snapshot fresh. On any listen
// error it falls back to polling and keeps trying to re-establish LISTEN.
func (w *Watcher) Run(ctx context.Context) {
	for {
		if err := w.listen(ctx); err != nil && ctx.Err() == nil {
			w.logger.Warn("config listener disconnected; retrying", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (w *Watcher) listen(ctx context.Context) error {
	conn, err := w.store.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN "+notifyChannel); err != nil {
		return err
	}
	w.logger.Info("listening for config changes", "channel", notifyChannel)

	for {
		// Wait for a notification, at most pollInterval. A deadline doubles
		// as the periodic reload so we cannot miss changes forever.
		waitCtx, cancel := context.WithTimeout(ctx, w.pollInterval)
		_, err := conn.Conn().WaitForNotification(waitCtx)
		cancel()

		switch {
		case err == nil:
			// Change signalled: absorb the burst before reloading.
			time.Sleep(w.debounce)
			w.drainPending(ctx, conn)
		case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
			// Poll fallback: reload anyway.
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			return err
		}

		reloadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := w.Load(reloadCtx); err != nil {
			w.logger.Error("config reload failed; keeping previous snapshot", "error", err)
		}
		cancel()
	}
}

// drainPending consumes notifications that queued up during the debounce so
// they do not trigger redundant reloads.
func (w *Watcher) drainPending(ctx context.Context, conn *pgxpool.Conn) {
	for {
		waitCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
		_, err := conn.Conn().WaitForNotification(waitCtx)
		cancel()
		if err != nil {
			return
		}
	}
}
