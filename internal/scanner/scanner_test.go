// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/netiface"
)

func idleWorker(ctx context.Context, _ chan<- Update) error { <-ctx.Done(); return ctx.Err() }

func TestScannerOnceWaitsForSweepAndDrainsUpdates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := New(Config{})
	started, release := make(chan struct{}), make(chan struct{})
	_, subnet, _ := net.ParseCIDR("192.168.0.0/22")
	hosts := netiface.SubnetIPs(subnet)
	workers := []namedWorker{{"arp", idleWorker}, {"mdns", idleWorker}, {"active", func(ctx context.Context, out chan<- Update) error {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		for _, ip := range hosts {
			select {
			case out <- Update{Source: "active", IP: ip, Alive: true, Time: time.Now()}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}}}
	done := make(chan error, 1)
	go func() { done <- s.runWorkers(ctx, workers, nil, true) }()
	<-started
	select {
	case err := <-done:
		t.Fatalf("returned before sweep completed: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("scanner did not finish")
	}
	if len(s.Snapshot()) != len(hosts) {
		t.Fatalf("lost queued observations: got %d, want %d", len(s.Snapshot()), len(hosts))
	}
	for range s.Events() {
	} // closed after workers and merger have finished
}

func TestScannerPropagatesWorkerFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	want := errors.New("capture interface disappeared")
	s := New(Config{})
	err := s.runWorkers(ctx, []namedWorker{{"arp", func(context.Context, chan<- Update) error { return want }}, {"mdns", idleWorker}, {"active", idleWorker}}, nil, false)
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want worker error", err)
	}
	for range s.Events() {
	}
}

func TestScannerCancellationIsNotSuccessfulOneShot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(Config{})
	if err := s.runWorkers(ctx, []namedWorker{{"arp", idleWorker}, {"active", idleWorker}}, nil, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}
