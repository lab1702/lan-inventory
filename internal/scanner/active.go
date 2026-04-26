package scanner

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/lab1702/lan-inventory/internal/probe"
)

// ActiveWorker periodically probes every host in Subnet plus any IP it has
// learned about, calling probe.Ping, probe.ScanPorts, and probe.ResolveHostname.
// One full sweep emits one Update per responding host.
type ActiveWorker struct {
	Subnet      *net.IPNet
	HostIPs     []net.IP // pre-enumerated subnet hosts
	Gateway     net.IP   // default-route gateway IP for the gateway-resolver hostname probe
	Interval    time.Duration
	WorkerCount int
	// KnownIPs returns the set of ARP-confirmed IP addresses (string form).
	// When set, the worker bypasses the liveness gate for these IPs and
	// runs the enrichment chain regardless — useful for hosts that
	// stealth-drop ICMP/TCP probes (Windows 11 default firewall) but
	// still respond to UDP-based queries like NBNS. Optional.
	KnownIPs func() map[string]struct{}
}

func (w *ActiveWorker) Run(ctx context.Context, out chan<- Update) error {
	if w.Interval == 0 {
		w.Interval = 30 * time.Second
	}
	if w.WorkerCount == 0 {
		w.WorkerCount = 32
	}

	// Run an initial sweep immediately, then on the interval.
	w.sweepOnce(ctx, out)
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
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
	jobs := make(chan net.IP, len(w.HostIPs))
	var wg sync.WaitGroup
	for i := 0; i < w.WorkerCount; i++ {
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
	// ICMP first — gives us TTL (used by OSDetect) and RTT.
	pingRes, _ := probe.Ping(ctx, ip.String())
	var ttl int
	var rtt time.Duration
	alive := pingRes.Alive
	if alive {
		ttl = pingRes.TTL
		rtt = pingRes.RTT
	} else if probe.TCPAlive(ctx, ip.String()) {
		// TCP signal of life (success or RST) — proceed without TTL/RTT.
		alive = true
	} else if isKnown {
		// ARP confirms this device exists. Run enrichment regardless —
		// the host may stealth-drop ICMP/TCP probes (Windows 11 Firewall
		// default) but still respond to UDP-based probes like NBNS.
		alive = true
	}
	if !alive {
		return
	}
	// Run the full enrichment chain.
	nbnsName := probe.NBNS(ctx, ip.String())
	update := Update{
		Source:        "active",
		Time:          time.Now(),
		IP:            ip,
		Alive:         true,
		RTT:           rtt,
		TTL:           ttl,
		Hostname:      probe.ResolveHostname(ctx, ip.String(), w.Gateway),
		OpenPorts:     probe.ScanPorts(ctx, ip.String(), probe.DefaultPorts(), 500*time.Millisecond),
		NBNSResponded: nbnsName != "",
	}
	select {
	case out <- update:
	case <-ctx.Done():
	}
}
