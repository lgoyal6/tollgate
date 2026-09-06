package proxy

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/lgoyal6/tollgate/internal/observability"
	"github.com/lgoyal6/tollgate/internal/resilience"
	"github.com/lgoyal6/tollgate/internal/store"
)

// The gateway holds the team's real provider credential, so the property that
// matters most about it is negative: it must not appear in anything the
// gateway emits. These tests assert that against the four places a secret
// actually escapes from a Go service - the log, the span, the response the
// client reads, and the response headers - by planting a sentinel and
// searching every byte of each.

// recording builds a proxy whose logs and spans are captured in memory.
// The tracer is assigned directly rather than through the global provider so
// the recorder cannot be disturbed by another test in this package.
func recording(t *testing.T, opts Options) (*Proxy, *bytes.Buffer, *tracetest.SpanRecorder) {
	t.Helper()
	logs := &bytes.Buffer{}
	if opts.Breakers == nil {
		opts.Breakers = resilience.NewBreakerGroup(resilience.DefaultBreakerConfig())
	}
	if opts.MaxBodyBuffer == 0 {
		opts.MaxBodyBuffer = 1 << 20
	}
	opts.MaxIdlePerHost = 4
	// LevelDebug so nothing is filtered out before the search runs.
	opts.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts.Metrics = observability.NewMetrics()

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })

	p := New(opts)
	p.tracer = tp.Tracer("tollgate/proxy-test")
	return p, logs, rec
}

// spanText flattens everything a span exports into one searchable string:
// name, every attribute key and value, the status description, and the same
// for each event. A secret hiding in any of them ends up in an exporter.
func spanText(t *testing.T, rec *tracetest.SpanRecorder) string {
	t.Helper()
	var b strings.Builder
	for _, s := range rec.Ended() {
		fmt.Fprintf(&b, "span %s status=%s %s\n", s.Name(), s.Status().Code, s.Status().Description)
		for _, kv := range s.Attributes() {
			fmt.Fprintf(&b, "  attr %s=%s\n", kv.Key, kv.Value.Emit())
		}
		for _, ev := range s.Events() {
			fmt.Fprintf(&b, "  event %s\n", ev.Name)
			for _, kv := range ev.Attributes {
				fmt.Fprintf(&b, "    attr %s=%s\n", kv.Key, kv.Value.Emit())
			}
		}
	}
	return b.String()
}

// TestProxySpanDoesNotCarryUpstreamCredentials covers the two credentials that
// ride along in a URL rather than in a header: userinfo on the configured
// upstream, which is how an operator wires up a basic-auth provider, and a
// query parameter, which is how several LLM providers take their key. Both
// used to be exported verbatim as the span's http.url attribute, so anyone
// with read access to the trace backend could read the provider credential
// without ever touching the gateway's environment.
func TestProxySpanDoesNotCarryUpstreamCredentials(t *testing.T) {
	const (
		upstreamPassword = "upstream-basic-auth-sentinel"
		queryCredential  = "query-param-key-sentinel"
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parsing upstream: %v", err)
	}
	u.User = url.UserPassword("svc", upstreamPassword)

	p, logs, rec := recording(t, Options{})
	req := httptest.NewRequest(http.MethodGet,
		"http://gw.example/api/messages?api_key="+queryCredential+"&model=claude", nil)
	resp, _ := send(p, routeTo(t, u.String(), nil), req)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", resp.Code, resp.Body)
	}

	spans := spanText(t, rec)
	if strings.Contains(spans, upstreamPassword) {
		t.Errorf("upstream basic-auth password reached a span attribute:\n%s", spans)
	}
	if strings.Contains(spans, queryCredential) {
		t.Errorf("query-string credential reached a span attribute:\n%s", spans)
	}
	if strings.Contains(logs.String(), upstreamPassword) || strings.Contains(logs.String(), queryCredential) {
		t.Errorf("credential reached a log line:\n%s", logs.String())
	}

	// The span still has to identify the upstream, or redaction has just
	// deleted the thing the operator needs.
	if !strings.Contains(spans, u.Host) {
		t.Errorf("span no longer names the upstream host %q:\n%s", u.Host, spans)
	}
}

// TestInjectedCredentialNeverEscapes plants the shared provider key in the
// environment exactly as a deployment does, then drives every path the proxy
// can take and searches the log, the spans and the client's whole response
// for it. The failure paths matter more than the success one: that is where a
// service usually leaks, by putting the request it could not complete into an
// error string.
func TestInjectedCredentialNeverEscapes(t *testing.T) {
	const secret = "sk-ant-provider-credential-sentinel"
	const envName = "TOLLGATE_TEST_UPSTREAM_CREDENTIAL"
	t.Setenv(envName, secret)

	injecting := func(r *store.Route) {
		r.UpstreamAuthHeader = "X-Api-Key"
		r.UpstreamAuthEnv = envName
		r.UpstreamAuthPrefix = ""
		r.RetryMax = 2
	}

	cases := []struct {
		name    string
		handler http.HandlerFunc
		// dead points the route at a closed listener instead of the handler.
		dead    bool
		timeout time.Duration
	}{
		{
			name: "upstream succeeds and echoes the credential back",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// A hostile or merely chatty upstream reflecting the header.
				w.Header().Set("X-Echoed-Key", r.Header.Get("X-Api-Key"))
				w.WriteHeader(http.StatusOK)
			},
		},
		{
			name: "upstream 500s until the retry budget is gone",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name: "upstream is unreachable",
			dead: true,
		},
		{
			name: "upstream exceeds the route timeout",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(150 * time.Millisecond)
				w.WriteHeader(http.StatusOK)
			},
			timeout: 20 * time.Millisecond,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := "http://127.0.0.1:1"
			if !tc.dead {
				srv := httptest.NewServer(tc.handler)
				t.Cleanup(srv.Close)
				target = srv.URL
			}

			p, logs, rec := recording(t, Options{})
			route := routeTo(t, target, func(r *store.Route) {
				injecting(r)
				if tc.timeout > 0 {
					r.Timeout = tc.timeout
				}
			})
			req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/messages", nil)
			resp, info := send(p, route, req)

			// Everything the client can observe, plus everything the gateway
			// recorded about the request.
			client := resp.Body.String()
			for k, vs := range resp.Header() {
				client += "\n" + k + ": " + strings.Join(vs, ",")
			}
			surfaces := map[string]string{
				"log":             logs.String(),
				"span":            spanText(t, rec),
				"client response": client,
				"reqctx error":    info.Error,
			}
			for where, text := range surfaces {
				if where == "client response" && !tc.dead && tc.timeout == 0 && resp.Code == http.StatusOK {
					// The success case deliberately has the upstream echo the
					// key back; the proxy is a proxy, so it forwards what the
					// upstream sent. That is the upstream's leak, not the
					// gateway's, and the assertion below covers the rest.
					continue
				}
				if strings.Contains(text, secret) {
					t.Errorf("provider credential appeared in the %s:\n%s", where, text)
				}
				if strings.Contains(text, envName) && where != "log" {
					t.Errorf("credential env var name appeared in the %s, which tells an attacker what to go looking for:\n%s", where, text)
				}
			}
		})
	}
}

// TestMissingCredentialFailsWithoutNamingTheValue pins the one error the proxy
// raises about the credential itself: it may name the environment variable so
// an operator can fix the deployment, and it must not reach the client.
func TestMissingCredentialFailsWithoutNamingTheValue(t *testing.T) {
	const envName = "TOLLGATE_TEST_UNSET_CREDENTIAL"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("upstream must not be reached when the credential is missing")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	p, _, _ := recording(t, Options{})
	route := routeTo(t, upstream.URL, func(r *store.Route) {
		r.UpstreamAuthHeader = "X-Api-Key"
		r.UpstreamAuthEnv = envName
	})
	req := httptest.NewRequest(http.MethodGet, "http://gw.example/api/messages", nil)
	resp, _ := send(p, route, req)

	if resp.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.Code)
	}
	if strings.Contains(resp.Body.String(), envName) {
		t.Errorf("client response names the credential env var: %s", resp.Body.String())
	}
}
