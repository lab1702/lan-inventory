// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/probe"
)

// ActiveWorker periodically probes every host in Subnet plus any IP it has
// learned about, calling probe.Ping, probe.ScanPorts, and probe.ResolveHostname.
// One full sweep emits one Update per responding host.
type ActiveWorker struct {
	Subnet       *net.IPNet
	HostIPs      []net.IP // pre-enumerated subnet hosts
	Gateway      net.IP   // default-route gateway IP for the gateway-resolver hostname probe
	Interval     time.Duration
	WorkerCount  int
	InitialDelay time.Duration
	Once         bool
	Rescan       <-chan struct{}
	// KnownIPs returns the set of ARP-confirmed IP addresses (string form).
	// When set, the worker bypasses the liveness gate for these IPs and
	// runs the enrichment chain regardless — useful for hosts that
	// stealth-drop ICMP/TCP probes (Windows 11 default firewall) but
	// still respond to UDP-based queries like NBNS. Optional.
	KnownIPs func() map[string]struct{}
	probes   *activeProbes
}

type activeProbes struct {
	ping     func(context.Context, string) (probe.PingResult, error)
	tcpAlive func(context.Context, string) bool
	nbns     func(context.Context, string) string
	hostname func(context.Context, string, net.IP) string
	ports    func(context.Context, string, []int, time.Duration) []model.Port
}

func (w *ActiveWorker) Run(ctx context.Context, out chan<- Update) error {
	// Defaults are resolved into locals rather than written back onto w: Run
	// can race a concurrent SweepOnce (UI rescan), so the worker's fields must
	// stay read-only after construction.
	interval := w.Interval
	if interval == 0 {
		interval = 30 * time.Second
	}

	if w.InitialDelay > 0 {
		timer := time.NewTimer(w.InitialDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	// A one-shot run returns only after every host has been probed.
	w.sweepOnce(ctx, out)
	if w.Once {
		return ctx.Err()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.sweepOnce(ctx, out)
		case <-w.Rescan:
			w.sweepOnce(ctx, out)
		}
	}
}

// SweepOnce probes every host once and returns when the sweep finishes. Used
// directly by --once mode.
func (w *ActiveWorker) SweepOnce(ctx context.Context, out chan<- Update) {
	w.sweepOnce(ctx, out)
}

func (w *ActiveWorker) sweepOnce(ctx context.Context, out chan<- Update) {
	// Snapshot the ARP-confirmed IPs once per sweep so all worker goroutines
	// see a consistent view of "known".
	var known map[string]struct{}
	if w.KnownIPs != nil {
		known = w.KnownIPs()
	}
	workerCount := w.WorkerCount
	if workerCount == 0 {
		workerCount = 32
	}
	jobs := make(chan net.IP, len(w.HostIPs))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				_, isKnown := known[ip.String()]
				w.probeOne(ctx, ip, isKnown, out)
			}
		}()
	}
	for _, ip := range w.HostIPs {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
}

func (w *ActiveWorker) probeOne(ctx context.Context, ip net.IP, isKnown bool, out chan<- Update) {
	if ctx.Err() != nil {
		return
	}
	p := w.probes
	if p == nil {
		p = &activeProbes{probe.Ping, probe.TCPAlive, probe.NBNS, probe.ResolveHostname, probe.ScanPorts}
	}
	// ICMP first — gives us TTL (used by OSDetect) and RTT.
	pingRes, _ := p.ping(ctx, ip.String())
	var ttl int
	var rtt time.Duration
	alive := pingRes.Alive
	if alive {
		ttl = pingRes.TTL
		rtt = pingRes.RTT
	} else if p.tcpAlive(ctx, ip.String()) {
		// TCP signal of life (success or RST) — proceed without TTL/RTT.
		alive = true
	}
	if !alive && !isKnown {
		return
	}
	// Historical ARP identity justifies trying more probes, but only a
	// current response from the host can refresh its last-seen timestamp.
	nbnsName := p.nbns(ctx, ip.String())
	ports := p.ports(ctx, ip.String(), probe.DefaultPorts(), 500*time.Millisecond)
	if !alive && nbnsName == "" && len(ports) == 0 {
		return
	}
	hostname := p.hostname(ctx, ip.String(), w.Gateway)
	if ctx.Err() != nil {
		return // do not publish a cancelled, partially completed port scan
	}
	update := Update{
		Source:        "active",
		Time:          time.Now(),
		IP:            ip,
		Alive:         true,
		RTT:           rtt,
		TTL:           ttl,
		Hostname:      hostname,
		OpenPorts:     ports,
		NBNSResponded: nbnsName != "",
	}
	select {
	case out <- update:
	case <-ctx.Done():
	}
}
