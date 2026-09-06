package middleware

import (
	"bytes"
	"compress/gzip"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A priced request that arrives gzipped must still be priced. If the body is
// only ever read raw, ShapeFromBody sees compressed bytes, fails to parse, and
// the request is silently treated as unpriceable: forwarded with NO hold taken.
// That is a billing bypass any client can trigger with one header.
func TestGzippedRequestIsStillPriced(t *testing.T) {
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	_, _ = zw.Write([]byte(pricedReq))
	_ = zw.Close()

	f := &fakeLedger{remaining: 100_000_000}
	h := Budget(f, false, slog.Default())(upstream(200, `{"usage":{"input_tokens":1000,"output_tokens":2000}}`))
	r := withTenant(httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body.Bytes())))
	r.Header.Set("Content-Encoding", "gzip")
	h.ServeHTTP(httptest.NewRecorder(), r)

	got := f.seen()
	if len(got) == 0 || got[0] != "reserve" {
		t.Errorf("gzipped request took no hold: calls=%v; a client can skip the budget with one header", got)
	}
}
