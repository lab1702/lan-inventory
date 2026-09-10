// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/netiface"
)

// Config describes the scanner's runtime parameters.
type Config struct {
	Iface         *netiface.Info
	MergerOptions MergerOptions
}

// Scanner wires the three workers and the merger together. Run or RunOnce
// may be called once per Scanner.
type Scanner struct {
	cfg           Config
	merger        *Merger
	events        chan model.DeviceEvent
	updates       chan Update
	sweepRequests chan struct{}
}

// New builds a fresh Scanner. Call Run or RunOnce to start it.
func New(cfg Config) *Scanner {
	return &Scanner{
		cfg:           cfg,
		merger:        NewMerger(cfg.MergerOptions),
		events:        make(chan model.DeviceEvent, 256),
		updates:       make(chan Update, 256),
		sweepRequests: make(chan struct{}, 1),
	}
}

// TriggerSweep queues a rescan in the active worker's bounded pool. Repeated
// requests are coalesced, and no independent producers outlive Run.
func (s *Scanner) TriggerSweep(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	select {
	case s.sweepRequests <- struct{}{}:
	default:
	}
}

func (s *Scanner) Events() <-chan model.DeviceEvent { return s.events }
func (s *Scanner) Snapshot() []*model.Device        { return s.merger.Snapshot() }

// Run starts periodic discovery and blocks until cancellation or a worker error.
func (s *Scanner) Run(ctx context.Context) error { return s.run(ctx, false) }

// RunOnce listens passively for eight seconds, completes one active sweep,
// stops all workers, and merges every emitted update before returning.
func (s *Scanner) RunOnce(ctx context.Context) error { return s.run(ctx, true) }

type namedWorker struct {
	name string
	run  func(context.Context, chan<- Update) error
}

func (s *Scanner) run(ctx context.Context, once bool) error {
	active := &ActiveWorker{
		Subnet:      s.cfg.Iface.Subnet,
		HostIPs:     netiface.SubnetIPs(s.cfg.Iface.Subnet),
		Gateway:     s.cfg.Iface.Gateway,
		WorkerCount: 32,
		KnownIPs:    s.merger.KnownIPs,
		Once:        once,
		Rescan:      s.sweepRequests,
	}
	if once {
		active.InitialDelay = 8 * time.Second
	}
	arp := &ARPWorker{Iface: s.cfg.Iface}
	mdns := &MDNSWorker{Iface: s.cfg.Iface}
	workers := []namedWorker{{"arp", arp.Run}, {"mdns", mdns.Run}, {"active", active.Run}}
	seeds := SeedFromKernelARP(s.cfg.Iface.Name, s.cfg.Iface.Subnet)
	return s.runWorkers(ctx, workers, seeds, once)
}

func (s *Scanner) runWorkers(parent context.Context, workers []namedWorker, seeds []Update, once bool) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer close(s.events)

	mergerDone := make(chan struct{})
	go func() {
		defer close(mergerDone)
		s.merger.Run(ctx, s.updates, s.events)
	}()
	// Start the merger before feeding a potentially /22-sized ARP cache.
seedLoop:
	for _, u := range seeds {
		select {
		case s.updates <- u:
		case <-ctx.Done():
			break seedLoop
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(workers))
	for _, w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := w.run(ctx, s.updates)
			if err == nil && ctx.Err() == nil && !(once && w.name == "active") {
				err = errors.New("stopped unexpectedly")
			}
			if err != nil && (!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) || ctx.Err() == nil) {
				errs <- fmt.Errorf("%s worker: %w", w.name, err)
				cancel()
			}
			if once && w.name == "active" {
				cancel()
			}
		}()
	}
	wg.Wait()
	cancel()
	<-mergerDone
	// Cancellation may win the merger's select with observations still queued.
	// All producers are now joined, so drain the finite remainder before snapshot.
	for len(s.updates) > 0 {
		s.merger.handleUpdate(<-s.updates, s.events)
	}
	select {
	case err := <-errs:
		return err
	default:
		return parent.Err()
	}
}
