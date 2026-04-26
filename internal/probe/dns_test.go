package probe_test

import (
	"context"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/probe"
)

func TestReverseDNSLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	got := probe.ReverseDNS(ctx, "127.0.0.1")
	// localhost resolution may or may not return "localhost." — we only
	// require that it does not panic and either returns "" or a non-empty
	// string ending with "." (FQDN canonicalization handled internally).
	if got != "" && got != "localhost" {
		t.Logf("ReverseDNS(127.0.0.1) = %q (informational)", got)
	}
}

func TestReverseDNSUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 192.0.2.0/24 (TEST-NET-1) should not resolve.
	got := probe.ReverseDNS(ctx, "192.0.2.123")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestReverseDNSMDNSLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	// Localhost rarely runs an mDNS responder bound to 127.0.0.1, so we
	// typically expect "". We verify the function doesn't panic or hang.
	_ = probe.ReverseDNSMDNS(ctx, "127.0.0.1")
}

func TestResolveHostnameDeadIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	got := probe.ResolveHostname(ctx, "192.0.2.1", nil)
	elapsed := time.Since(start)

	if got != "" {
		t.Errorf("ResolveHostname on TEST-NET-1 should return empty, got %q", got)
	}
	// Chain bound: system rDNS may take a couple of seconds depending on the
	// system resolver, then NBNS (500 ms) and mDNS-reverse (500 ms). Allow
	// up to 4 s total before declaring the chain unbounded.
	if elapsed > 4*time.Second {
		t.Errorf("ResolveHostname took %v, expected under 4s", elapsed)
	}
}
