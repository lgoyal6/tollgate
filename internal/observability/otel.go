package observability

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// SetupTracing installs the global propagator and, when an OTLP endpoint is
// configured, a sampling TracerProvider. Without an endpoint the gateway
// still *propagates* W3C trace context to upstreams (extract + inject work
// on non-recording spans); it just exports nothing.
func SetupTracing(ctx context.Context, serviceName, version string, ratio float64, logger *slog.Logger) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		logger.Info("OTEL_EXPORTER_OTLP_ENDPOINT unset; tracing export disabled, propagation still on")
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	res := sdkresource.NewSchemaless(
		attribute.String("service.name", serviceName),
		attribute.String("service.version", version),
	)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	otel.SetTracerProvider(tp)
	logger.Info("tracing enabled", "endpoint", endpoint, "sample_ratio", ratio)

	return func(shutdownCtx context.Context) error {
		ctx, cancel := context.WithTimeout(shutdownCtx, 5*time.Second)
		defer cancel()
		return tp.Shutdown(ctx)
	}, nil
}
