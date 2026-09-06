package ratelimit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/lgoyal6/tollgate/internal/store"
)

// The limiter's span is the first thing on the request path to talk to a network
// dependency, and the two things that must never be on it are the credential in the
// Redis DSN and anything that is one value per tenant or per request. A trace
// backend retains attributes and shows them to anyone with the URL.
func TestLimiterSpanCarriesNoCredentialAndNoIdentifier(t *testing.T) {
	const (
		password = "redis-password-sentinel"
		tenantID = "tenant-sentinel-0001"
		uniq     = "request-id-sentinel-0002"
	)

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(previous) })
	tracer = provider.Tracer("tollgate/ratelimit")
	t.Cleanup(func() { tracer = otel.Tracer("tollgate/ratelimit") })

	// A client pointed at an address that cannot resolve, with the sentinel IN the
	// host so it is present in the driver's own error string, and the password in
	// the DSN exactly as a managed Redis hands it over. The call must fail: the
	// failure is the point, because a service usually leaks by putting what it could
	// not do into an error, and go-redis's dial error quotes the address verbatim.
	client := redis.NewClient(&redis.Options{
		Addr:     password + ".invalid:6379",
		Password: password,
	})
	t.Cleanup(func() { _ = client.Close() })

	limiter := NewRedisLimiter(client)
	policy := Policy{Algorithm: store.AlgoSlidingWindow, Limit: 10, Window: time.Second}
	if err := policy.Validate(); err != nil {
		t.Fatalf("the test policy is invalid, so the Redis call is never reached: %v", err)
	}
	_, err := limiter.Allow(context.Background(), tenantID, policy, uniq)
	if err == nil {
		t.Fatal("expected the limiter call to fail against an unresolvable host")
	}
	if !strings.Contains(err.Error(), password) {
		t.Fatalf("the driver error does not quote the DSN, so this test cannot see a "+
			"leak of it; got %v", err)
	}

	var text strings.Builder
	ended := recorder.Ended()
	if len(ended) == 0 {
		t.Fatal("the limiter emitted no span at all")
	}
	for _, s := range ended {
		text.WriteString(s.Name() + " " + s.Status().Description + "\n")
		for _, kv := range s.Attributes() {
			text.WriteString("  " + string(kv.Key) + "=" + kv.Value.Emit() + "\n")
		}
		for _, ev := range s.Events() {
			text.WriteString("  event " + ev.Name + "\n")
			for _, kv := range ev.Attributes {
				text.WriteString("    " + string(kv.Key) + "=" + kv.Value.Emit() + "\n")
			}
		}
	}
	spans := text.String()

	for _, forbidden := range []string{password, tenantID, uniq} {
		if strings.Contains(spans, forbidden) {
			t.Errorf("%q reached the limiter span:\n%s", forbidden, spans)
		}
	}
	// And it still says what failed, or redaction has deleted the thing an
	// operator needs.
	if !strings.Contains(spans, "ratelimit.allow") || !strings.Contains(spans, "redis") {
		t.Errorf("the span no longer identifies the failing dependency:\n%s", spans)
	}
}
