// Command upstream is the demo backend the gateway proxies to. It echoes
// request details as JSON and can simulate latency and failures, per process
// (env) or per request (query params), which is how the k6 scenarios and the
// circuit breaker demo shape upstream behaviour.
//
//	BASE_DELAY_MS / JITTER_MS   baseline artificial latency
//	ERROR_RATE                  0..1 fraction of requests answered 500
//	?delay_ms=200&status=503    per-request overrides
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"time"
)

type echo struct {
	Instance string            `json:"instance"`
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Tenant   string            `json:"tenant"`
	Request  string            `json:"request_id"`
	Trace    string            `json:"traceparent"`
	DelayMs  int64             `json:"delay_ms"`
	Headers  map[string]string `json:"headers"`
}

func main() {
	addr := getenv("LISTEN_ADDR", ":9000")
	baseDelay := envInt("BASE_DELAY_MS", 0)
	jitter := envInt("JITTER_MS", 0)
	errorRate := envFloat("ERROR_RATE", 0)
	hostname, _ := os.Hostname()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		delay := time.Duration(baseDelay) * time.Millisecond
		if jitter > 0 {
			delay += time.Duration(rand.Int64N(jitter)) * time.Millisecond
		}
		if q := r.URL.Query().Get("delay_ms"); q != "" {
			if ms, err := strconv.ParseInt(q, 10, 64); err == nil && ms >= 0 && ms <= 60_000 {
				delay = time.Duration(ms) * time.Millisecond
			}
		}
		if delay > 0 {
			time.Sleep(delay)
		}

		status := http.StatusOK
		if errorRate > 0 && rand.Float64() < errorRate {
			status = http.StatusInternalServerError
		}
		if q := r.URL.Query().Get("status"); q != "" {
			if s, err := strconv.Atoi(q); err == nil && s >= 200 && s <= 599 {
				status = s
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Instance", hostname)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(echo{
			Instance: hostname,
			Method:   r.Method,
			Path:     r.URL.Path,
			Tenant:   r.Header.Get("X-Tollgate-Tenant"),
			Request:  r.Header.Get("X-Request-Id"),
			Trace:    r.Header.Get("Traceparent"),
			DelayMs:  delay.Milliseconds(),
			Headers: map[string]string{
				"X-Forwarded-For":  r.Header.Get("X-Forwarded-For"),
				"X-Forwarded-Host": r.Header.Get("X-Forwarded-Host"),
				// Demo-only echo of the gateway's credential-injection header
				// so `make up` users can verify -auth-env wiring end to end.
				"X-Provider-Key": r.Header.Get("X-Provider-Key"),
			},
		})
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("upstream %s listening on %s (base_delay=%dms jitter=%dms error_rate=%.2f)",
		hostname, addr, baseDelay, jitter, errorRate)
	log.Fatal(srv.ListenAndServe())
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}
