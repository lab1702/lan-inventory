// SPDX-License-Identifier: GPL-2.0-or-later

package probe_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/probe"
)

func startListener(t *testing.T) (host string, port int, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return "127.0.0.1", addr.Port, func() { l.Close() }
}

func TestScanPortsOpenAndClosed(t *testing.T) {
	host, port, stop := startListener(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Closed port: pick the listener's port + 1 (very likely closed).
	closedPort := port + 1
	results := probe.ScanPorts(ctx, host, []int{port, closedPort}, 200*time.Millisecond)

	if len(results) != 1 {
		t.Fatalf("expected 1 open port, got %d (%v)", len(results), results)
	}
	if results[0].Number != port || results[0].Proto != "tcp" {
		t.Errorf("got %+v, want port %d/tcp", results[0], port)
	}
}

func TestScanPortsRespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := probe.ScanPorts(ctx, "127.0.0.1", []int{1, 2, 3}, 100*time.Millisecond)
	if len(results) != 0 {
		t.Errorf("expected no results on cancelled ctx, got %v", results)
	}
}

func TestServiceLabel(t *testing.T) {
	cases := map[int]string{22: "ssh", 53: "dns", 80: "http", 443: "https", 9999: ""}
	for n, want := range cases {
		got := probe.ServiceLabel(n)
		if got != want {
			t.Errorf("ServiceLabel(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestDefaultPorts(t *testing.T) {
	if len(probe.DefaultPorts()) < 10 {
		t.Errorf("DefaultPorts seems too short: %v", probe.DefaultPorts())
	}
	// must be sorted ascending and unique
	prev := -1
	for _, p := range probe.DefaultPorts() {
		if p <= prev {
			t.Errorf("ports not sorted ascending unique: %v", probe.DefaultPorts())
			break
		}
		prev = p
	}
	_ = strconv.Itoa(0) // silence unused import if test pruned later
}