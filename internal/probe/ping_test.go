// SPDX-License-Identifier: GPL-2.0-or-later

package probe_test

import (
	"context"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/probe"
)

func TestPingLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := probe.Ping(ctx, "127.0.0.1")
	if err != nil {
		t.Skipf("Ping failed (raw socket unavailable in test env): %v", err)
	}
	if !res.Alive {
		t.Errorf("expected localhost alive")
	}
	if res.RTT <= 0 {
		t.Errorf("expected positive RTT, got %v", res.RTT)
	}
	if res.TTL <= 0 {
		t.Errorf("expected positive TTL, got %d", res.TTL)
	}
}

func TestPingDeadIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use a documentation-reserved address (RFC 5737) that should not respond.
	res, err := probe.Ping(ctx, "192.0.2.1")
	if err != nil {
		t.Skipf("Ping setup failed (raw socket unavailable): %v", err)
	}
	if res.Alive {
		t.Errorf("expected 192.0.2.1 not alive, got %v", res)
	}
}