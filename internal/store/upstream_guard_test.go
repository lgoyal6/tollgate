package store

import (
	"net/url"
	"testing"
	"time"
)

func TestForbiddenUpstream(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		// The thing this exists for.
		{"AWS and Azure IMDS", "169.254.169.254", true},
		{"IMDS with a port", "169.254.169.254:80", true},
		{"anything else in the link-local range", "169.254.0.23", true},
		{"the hex spelling of IMDS", "0xa9fea9fe", true},
		{"the decimal spelling of IMDS", "2852039166", true},
		{"AWS IMDS over IPv6", "fd00:ec2::254", true},
		{"AWS IMDS over IPv6, bracketed with a port", "[fd00:ec2::254]:80", true},
		{"an IPv6 link-local address", "fe80::1", true},
		{"the GCP metadata hostname", "metadata.google.internal", true},
		{"the GCP metadata hostname, uppercased", "Metadata.Google.Internal", true},
		{"the short GCP metadata hostname", "metadata.goog", true},

		// The upstreams this repo's own deployments actually use. Refusing
		// any of these would break compose, kind and every self-hosted
		// deployment, which is the failure mode that gets a guard disabled.
		{"the compose demo upstream", "localhost:9000", false},
		{"loopback", "127.0.0.1:8080", false},
		{"IPv6 loopback", "::1", false},
		{"a kind pod address", "10.244.1.7:8080", false},
		{"a private RFC 1918 upstream", "192.168.1.10", false},
		{"the other RFC 1918 block", "172.16.4.9:443", false},
		{"a real provider", "api.anthropic.com", false},
		{"a hostname that merely starts the same way", "metadata.example.com", false},
		{"a bare internal service name", "metadata", false},
		{"a public address", "203.0.113.9", false},
		{"nothing at all", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, got := ForbiddenUpstream(tt.host)
			if got != tt.want {
				t.Fatalf("ForbiddenUpstream(%q) = %v (%q), want %v", tt.host, got, reason, tt.want)
			}
			if got && reason == "" {
				t.Errorf("ForbiddenUpstream(%q) refused with no reason to show an operator", tt.host)
			}
			if !got && reason != "" {
				t.Errorf("ForbiddenUpstream(%q) allowed but gave a reason %q", tt.host, reason)
			}
		})
	}
}

// The route upsert path has to refuse it too, or the request-time check is
// the only thing standing between a typo and a credential going to the
// metadata service on every request until somebody notices.
func TestRouteValidationRefusesAMetadataUpstream(t *testing.T) {
	base := RouteSpec{
		TenantID: "acme", PathPrefix: "/api/", Timeout: time.Second,
		HedgeDelay: 50 * time.Millisecond,
	}
	tests := []struct {
		name     string
		upstream string
		wantErr  bool
	}{
		{"a metadata endpoint", "http://169.254.169.254/latest/meta-data/", true},
		{"a metadata endpoint by name", "http://metadata.google.internal/computeMetadata/v1/", true},
		{"the decimal spelling", "http://2852039166/", true},
		{"a private upstream", "http://10.4.0.11:8080", false},
		{"the compose upstream", "http://upstream-a:9000", false},
		{"a real provider", "https://api.anthropic.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := base
			spec.Upstream = tt.upstream
			err := spec.Validate()
			if tt.wantErr != (err != nil) {
				t.Fatalf("Validate() error = %v, want error: %v", err, tt.wantErr)
			}
			if err == nil {
				return
			}
			// The message goes back to an operator over the management API,
			// so it has to be marked as being about their own input.
			if _, ok := err.(*ValidationError); !ok {
				t.Fatalf("error is %T, want *ValidationError so the API may repeat it", err)
			}
			if _, err := url.Parse(tt.upstream); err != nil {
				t.Fatalf("test fixture is not a URL: %v", err)
			}
		})
	}
}
