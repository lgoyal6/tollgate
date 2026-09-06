// Command tollgate-outbox runs the two halves of the transactional outbox as
// separate processes, which is what makes the crash tests mean anything: the
// relay can be killed without taking the consumer with it, and the consumer's
// database is genuinely a different database from the gateway's.
//
//	tollgate-outbox migrate-sink -db $BILLING_URL
//	tollgate-outbox sink         -db $BILLING_URL -addr :9411
//	tollgate-outbox seal         -db $DATABASE_URL -tenant acme -window ... -requests 120
//	tollgate-outbox relay        -db $DATABASE_URL -sink http://localhost:9411
//	tollgate-outbox reconcile    -db $DATABASE_URL -sink http://localhost:9411
//	tollgate-outbox status       -db $DATABASE_URL
//
// -crash names a point at which the process kills itself with SIGKILL. It is
// for the crash tests and nothing else; unset, the hook is nil.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lgoyal6/tollgate/internal/outbox"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "migrate-sink":
		err = migrateSink(ctx, os.Args[2:])
	case "sink":
		err = runSink(ctx, os.Args[2:])
	case "seal":
		err = seal(ctx, os.Args[2:])
	case "relay":
		err = relay(ctx, os.Args[2:])
	case "reconcile":
		err = reconcile(ctx, os.Args[2:])
	case "status":
		err = status(ctx, os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tollgate-outbox <migrate-sink|sink|seal|relay|reconcile|status> [flags]")
	os.Exit(2)
}

func connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	if url == "" {
		return nil, errors.New("-db is required")
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// killer returns a Crasher that really kills this process at the named point.
//
// SIGKILL, not panic and not os.Exit: a panic runs deferred functions and an
// exit flushes buffers, and either would let the process tidy up in a way a
// power cut or an OOM kill never would. SIGKILL cannot be caught, blocked or
// ignored, so what survives is only what Postgres already committed.
func killer(point string) outbox.Crasher {
	if point == "" {
		return nil
	}
	want := outbox.CrashPoint(point)
	return func(p outbox.CrashPoint) {
		if p != want {
			return
		}
		fmt.Fprintf(os.Stderr, "crash point %s reached; SIGKILL to pid %d\n", p, os.Getpid())
		_ = os.Stderr.Sync()
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		select {} // unreachable
	}
}

func migrateSink(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("migrate-sink", flag.ExitOnError)
	db := fs.String("db", os.Getenv("BILLING_URL"), "consumer database URL")
	_ = fs.Parse(args)
	pool, err := connect(ctx, *db)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := outbox.MigrateSink(ctx, pool); err != nil {
		return err
	}
	fmt.Println("sink schema ready")
	return nil
}

func runSink(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sink", flag.ExitOnError)
	db := fs.String("db", os.Getenv("BILLING_URL"), "consumer database URL")
	addr := fs.String("addr", ":9411", "listen address")
	dedupe := fs.Bool("dedupe", true, "apply inbox deduplication (false is the negative control)")
	_ = fs.Parse(args)
	pool, err := connect(ctx, *db)
	if err != nil {
		return err
	}
	defer pool.Close()
	sink := &outbox.BillingSink{Pool: pool, Dedupe: *dedupe}
	srv := &http.Server{Addr: *addr, Handler: sink.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	fmt.Printf("billing sink listening on %s (dedupe=%v)\n", *addr, *dedupe)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func seal(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	db := fs.String("db", os.Getenv("DATABASE_URL"), "gateway database URL")
	tenant := fs.String("tenant", "", "tenant id")
	window := fs.String("window", "", "window start, RFC3339")
	requests := fs.Int64("requests", 0, "requests in the window")
	limited := fs.Int64("limited", 0, "rate-limited requests in the window")
	mode := fs.String("mode", "outbox", "outbox | dual-write (dual-write is the negative control)")
	sinkURL := fs.String("sink", "", "sink base URL, dual-write mode only")
	crash := fs.String("crash", "", "crash point: after_commit")
	_ = fs.Parse(args)

	start, err := time.Parse(time.RFC3339, *window)
	if err != nil {
		return fmt.Errorf("parsing -window: %w", err)
	}
	pool, err := connect(ctx, *db)
	if err != nil {
		return err
	}
	defer pool.Close()

	w := outbox.Window{
		TenantID: *tenant, WindowStart: start, WindowEnd: start.Add(time.Minute),
		Requests: *requests, Admitted: *requests - *limited, Limited: *limited,
	}
	switch *mode {
	case "outbox":
		n, err := outbox.SealWindows(ctx, pool, []outbox.Window{w}, killer(*crash))
		if err != nil {
			return err
		}
		fmt.Printf("sealed %d window(s); key=%s\n", n, outbox.UsageKey(*tenant, start))
	case "dual-write":
		if *sinkURL == "" {
			return errors.New("-sink is required in dual-write mode")
		}
		if err := outbox.SealWindowsDualWrite(ctx, pool, []outbox.Window{w}, outbox.HTTPSink{BaseURL: *sinkURL}, killer(*crash)); err != nil {
			return err
		}
		fmt.Printf("dual-write completed; key=%s\n", outbox.UsageKey(*tenant, start))
	default:
		return fmt.Errorf("unknown -mode %q", *mode)
	}
	return nil
}

func newRelay(pool *pgxpool.Pool, sinkURL string, noLookup bool, lease time.Duration, crash string) *outbox.Relay {
	host, _ := os.Hostname()
	return &outbox.Relay{
		Pool:  pool,
		Sink:  outbox.HTTPSink{BaseURL: sinkURL, LookupDisabled: noLookup},
		Owner: fmt.Sprintf("%s/%d", host, os.Getpid()),
		Lease: lease,
		Batch: 32,
		Crash: killer(crash),
	}
}

func relay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	db := fs.String("db", os.Getenv("DATABASE_URL"), "gateway database URL")
	sinkURL := fs.String("sink", "", "sink base URL")
	once := fs.Bool("once", true, "run a single pass and exit")
	interval := fs.Duration("interval", 2*time.Second, "poll interval when not -once")
	lease := fs.Duration("lease", 30*time.Second, "attempt lease")
	crash := fs.String("crash", "", "crash point: before_send | after_send")
	_ = fs.Parse(args)
	if *sinkURL == "" {
		return errors.New("-sink is required")
	}
	pool, err := connect(ctx, *db)
	if err != nil {
		return err
	}
	defer pool.Close()
	r := newRelay(pool, *sinkURL, false, *lease, *crash)

	run := func() error {
		res, err := r.Once(ctx)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(res)
		fmt.Printf("pass %s\n", b)
		return nil
	}
	if *once {
		return run()
	}
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	for {
		if err := run(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func reconcile(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reconcile", flag.ExitOnError)
	db := fs.String("db", os.Getenv("DATABASE_URL"), "gateway database URL")
	sinkURL := fs.String("sink", "", "sink base URL")
	noLookup := fs.Bool("no-lookup", false, "model a downstream that cannot be asked")
	expire := fs.Bool("expire", true, "expire dead leases into UNKNOWN before reconciling")
	lease := fs.Duration("lease", 30*time.Second, "attempt lease")
	_ = fs.Parse(args)
	if *sinkURL == "" {
		return errors.New("-sink is required")
	}
	pool, err := connect(ctx, *db)
	if err != nil {
		return err
	}
	defer pool.Close()
	r := newRelay(pool, *sinkURL, *noLookup, *lease, "")
	if *expire {
		n, err := r.ExpireLeases(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("expired %d lease(s) into UNKNOWN\n", n)
	}
	res, err := r.Reconcile(ctx)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(res)
	fmt.Printf("reconcile %s\n", b)
	return nil
}

func status(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	db := fs.String("db", os.Getenv("DATABASE_URL"), "gateway database URL")
	_ = fs.Parse(args)
	pool, err := connect(ctx, *db)
	if err != nil {
		return err
	}
	defer pool.Close()
	counts, err := outbox.Counts(ctx, pool)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(counts)
	fmt.Printf("outbox %s\n", b)
	return nil
}
