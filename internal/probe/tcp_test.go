package probe_test

import (
	"context"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/probe"
)

func TestTCPAliveDeadIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// 192.0.2.1 is in TEST-NET-1 (RFC 5737). Should not respond on any
	// of the probed ports — return false within the per-port timeout.
	if probe.TCPAlive(ctx, "192.0.2.1") {
		t.Errorf("TCPAlive on TEST-NET-1 should be false")
	}
}

func TestTCPAliveLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Localhost responds to TCP connection attempts even with no listener:
	// the kernel sends RST (connection refused), which counts as alive.
	if !probe.TCPAlive(ctx, "127.0.0.1") {
		t.Errorf("TCPAlive on 127.0.0.1 should be true (RST counts as alive)")
	}
}
