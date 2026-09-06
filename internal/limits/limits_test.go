package limits_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/lgoyal6/tollgate/internal/limits"
)

func TestCappedBodyAllowsExactlyTheLimit(t *testing.T) {
	payload := strings.Repeat("x", 1024)
	b := limits.NewCappedBody(io.NopCloser(strings.NewReader(payload)), 1024)
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 1024 {
		t.Errorf("read %d bytes, want 1024", len(got))
	}
}

func TestCappedBodyFailsOneByteOver(t *testing.T) {
	payload := strings.Repeat("x", 1025)
	b := limits.NewCappedBody(io.NopCloser(strings.NewReader(payload)), 1024)
	_, err := io.ReadAll(b)
	if !errors.Is(err, limits.ErrRequestTooLarge) {
		t.Fatalf("err = %v, want ErrRequestTooLarge", err)
	}
}

// The cap must fail rather than truncate: a truncated body is a different
// request, which the upstream would answer and bill for.
func TestCappedBodyDoesNotSilentlyTruncate(t *testing.T) {
	payload := strings.Repeat("x", 4096)
	b := limits.NewCappedBody(io.NopCloser(strings.NewReader(payload)), 1024)
	var out bytes.Buffer
	_, err := io.Copy(&out, b)
	if !errors.Is(err, limits.ErrRequestTooLarge) {
		t.Fatalf("err = %v, want ErrRequestTooLarge", err)
	}
	if out.Len() > 1024 {
		t.Errorf("copied %d bytes past the cap", out.Len()-1024)
	}
}

func gzipOf(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := io.Copy(zw, io.LimitReader(zeroes{}, int64(n))); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	zw.Close()
	return buf.Bytes()
}

type zeroes struct{}

func (zeroes) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestInflateRefusesABomb(t *testing.T) {
	// 64 MiB of plaintext in a few KiB on the wire: the reason a wire-byte cap
	// is not a size limit.
	raw := gzipOf(t, 64<<20)
	if len(raw) > 1<<20 {
		t.Fatalf("fixture is %d wire bytes, expected a high ratio", len(raw))
	}
	_, err := limits.Inflate(raw, 8<<20, 1<<20)
	if !errors.Is(err, limits.ErrDecompressedTooLarge) {
		t.Fatalf("err = %v, want ErrDecompressedTooLarge", err)
	}
}

func TestInflateAllowsExactlyTheLimit(t *testing.T) {
	raw := gzipOf(t, 1<<20)
	prefix, err := limits.Inflate(raw, 1<<20, 4096)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	if len(prefix) != 4096 {
		t.Errorf("prefix = %d bytes, want the keep cap of 4096", len(prefix))
	}
}

// The point of the keep cap is that proving an expansion is over the limit
// does not require holding the expansion.
func TestInflateRetainsOnlyTheKeepPrefix(t *testing.T) {
	raw := gzipOf(t, 4<<20)
	prefix, err := limits.Inflate(raw, 8<<20, 1024)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	if len(prefix) != 1024 {
		t.Fatalf("prefix = %d bytes, want 1024", len(prefix))
	}
}

func TestInflateRejectsMalformedGzip(t *testing.T) {
	if _, err := limits.Inflate([]byte("not gzip at all"), 1<<20, 1024); err == nil {
		t.Fatal("want an error for a body that is not gzip")
	}
}
