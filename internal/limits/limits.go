// Package limits holds the abuse bounds a single request is held to, and the
// two stream primitives that enforce the byte ones.
//
// It is its own package because the bounds are enforced in two places that
// must not import each other: the middleware chain (which refuses before any
// spend hold is taken) and the proxy (which is where a body is finally read
// and a response is finally relayed). Both need the same sentinels, so the
// sentinels live below both.
//
// Every field is a hard cap and 0 means "not enforced", so a deployment that
// wants the old unbounded behaviour has to ask for it rather than get it by
// omission.
package limits

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"time"
)

// Config is the full set of per-request bounds.
type Config struct {
	// MaxRequestBytes caps the body as it arrives on the wire. Checked
	// against Content-Length first, which costs nothing, and enforced while
	// reading for chunked uploads, which declare no length.
	MaxRequestBytes int64
	// MaxDecompressedBytes caps what a compressed body expands to. A wire cap
	// alone is not a size limit: measured on this repo's own harness, padded
	// JSON gzips at roughly 510:1, so a body under an 8 MiB wire cap can
	// still be 4 GiB of work for whoever inflates it.
	MaxDecompressedBytes int64
	// MaxResponseBytes caps what the gateway will relay back from an
	// upstream. The gateway pays egress for every one of those bytes and does
	// not choose them.
	MaxResponseBytes int64
	// MaxInFlightPerTenant is how many of a tenant's requests may occupy the
	// gateway at once. Per tenant rather than global on purpose: a global cap
	// lets one caller's fan-out refuse everybody else's traffic, which is the
	// starvation this is supposed to prevent.
	MaxInFlightPerTenant int
	// MaxQueuePerTenant is how many more may wait for a slot before the
	// tenant is refused outright. A queue absorbs a burst; an unbounded queue
	// only converts a rejection the client could retry into a timeout it
	// cannot.
	MaxQueuePerTenant int
	// QueueWait is how long a queued request waits before being refused.
	QueueWait time.Duration
	// MaxRequestDuration bounds one request end to end, across every retry
	// and backoff. Without it the ceiling is the route timeout multiplied by
	// whatever retry count happens to be in Postgres.
	MaxRequestDuration time.Duration
}

var (
	// ErrRequestTooLarge means the request body passed MaxRequestBytes. It is
	// returned by the body reader, so it surfaces wherever the body is
	// actually consumed.
	ErrRequestTooLarge = errors.New("limits: request body exceeds the configured maximum")
	// ErrDecompressedTooLarge means a compressed body expanded past
	// MaxDecompressedBytes.
	ErrDecompressedTooLarge = errors.New("limits: decompressed request body exceeds the configured maximum")
	// ErrResponseTooLarge means an upstream response passed MaxResponseBytes.
	ErrResponseTooLarge = errors.New("limits: upstream response exceeds the configured maximum")
)

// CappedBody is a request body that fails rather than silently truncating
// once limit bytes have been read.
//
// Truncating would be worse than failing: the upstream would receive a
// prefix of the caller's request, answer it, and bill for it, and nothing
// downstream would know the difference.
type CappedBody struct {
	rc    io.ReadCloser
	limit int64
	read  int64
}

// NewCappedBody wraps rc so that reading more than limit bytes fails with
// ErrRequestTooLarge.
func NewCappedBody(rc io.ReadCloser, limit int64) *CappedBody {
	return &CappedBody{rc: rc, limit: limit}
}

func (c *CappedBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	room := c.limit - c.read
	if room < 0 {
		room = 0
	}
	// One byte past the cap, so a body of exactly limit bytes still reaches
	// EOF normally while limit+1 is detected on the read that produces it.
	if int64(len(p)) > room+1 {
		p = p[:room+1]
	}
	n, err := c.rc.Read(p)
	c.read += int64(n)
	if c.read > c.limit {
		return 0, ErrRequestTooLarge
	}
	return n, err
}

func (c *CappedBody) Close() error { return c.rc.Close() }

// Count reports how many bytes have been taken off the wire so far.
func (c *CappedBody) Count() int64 { return c.read }

// Inflate expands a gzip body under two separate caps.
//
// total is what stops a bomb. keep is how much of the result is retained for
// the budget estimator to price; everything past it is counted and dropped,
// so proving that a body expands to 512 MiB costs CPU and a 32 KiB copy
// buffer rather than 512 MiB of heap.
//
// The returned prefix is the decompressed head, capped at keep bytes.
func Inflate(raw []byte, total, keep int64) (prefix []byte, err error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	hw := &headWriter{keep: keep}
	// total+1 so "exactly at the cap" and "over it" are distinguishable.
	if _, err := io.Copy(hw, io.LimitReader(zr, total+1)); err != nil {
		return nil, err
	}
	if hw.n > total {
		return nil, ErrDecompressedTooLarge
	}
	return hw.buf.Bytes(), nil
}

// headWriter counts everything and keeps only the first keep bytes.
type headWriter struct {
	buf  bytes.Buffer
	keep int64
	n    int64
}

func (h *headWriter) Write(p []byte) (int, error) {
	if room := h.keep - int64(h.buf.Len()); room > 0 {
		if int64(len(p)) < room {
			room = int64(len(p))
		}
		h.buf.Write(p[:room])
	}
	h.n += int64(len(p))
	return len(p), nil
}
