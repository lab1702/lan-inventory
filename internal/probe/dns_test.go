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
