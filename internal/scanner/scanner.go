package scanner

import (
	"context"
	"sync"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/netiface"
)

// Config describes the scanner's runtime parameters.
type Config struct {
	Iface         *netiface.Info
	MergerOptions MergerOptions
	OnceMode      bool // if true, ActiveWorker runs a single sweep then context is cancelled by the caller
}

// Scanner wires the three workers and the merger together.
type Scanner struct {
	cfg     Config
	merger  *Merger
	events  chan model.DeviceEvent
	updates chan Update
	active  *ActiveWorker
}

// New builds a fresh Scanner. Call Run to start it.
func New(cfg Config) *Scanner {
	return &Scanner{
		cfg:     cfg,
		merger:  NewMerger(cfg.MergerOptions),
		events:  make(chan model.DeviceEvent, 256),
		updates: make(chan Update, 256),
	}
}

// TriggerSweep runs a single out-of-band active sweep using the same worker
// pool as the periodic scan. Safe to call concurrently with Run.
func (s *Scanner) TriggerSweep(ctx context.Context) {
	if s.active == nil {
		return
	}
	s.active.SweepOnce(ctx, s.updates)
}

// Events returns a read-only channel of DeviceEvent.
func (s *Scanner) Events() <-chan model.DeviceEvent { return s.events }

// Snapshot returns a copy of the current device map.
func (s *Scanner) Snapshot() []*model.Device { return s.merger.Snapshot() }

// Run starts the workers and the merger. Blocks until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) error {
	hosts := netiface.SubnetIPs(s.cfg.Iface.Subnet)

	arp := &ARPWorker{IfaceName: s.cfg.Iface.Name}
	mdns := &MDNSWorker{IfaceName: s.cfg.Iface.Name}
	s.active = &ActiveWorker{
		Subnet:      s.cfg.Iface.Subnet,
		HostIPs:     hosts,
		WorkerCount: 32,
	}
	active := s.active

	var wg sync.WaitGroup

	wg.Add(1)
	go func() { defer wg.Done(); s.merger.Run(ctx, s.updates, s.events) }()

	wg.Add(1)
	go func() { defer wg.Done(); _ = arp.Run(ctx, s.updates) }()

	wg.Add(1)
	go func() { defer wg.Done(); _ = mdns.Run(ctx, s.updates) }()

	wg.Add(1)
	go func() { defer wg.Done(); _ = active.Run(ctx, s.updates) }()

	wg.Wait()
	close(s.events)
	return nil
}
