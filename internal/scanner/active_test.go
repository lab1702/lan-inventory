// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/netiface"
	"github.com/lab1702/lan-inventory/internal/probe"
)

func silentProbes() *activeProbes {
	return &activeProbes{
		ping:     func(context.Context, string) (probe.PingResult, error) { return probe.PingResult{}, nil },
		tcpAlive: func(context.Context, string) bool { return false },
		nbns:     func(context.Context, string) string { return "" },
		hostname: func(context.Context, string, net.IP) string { return "cached-router-name" },
		ports:    func(context.Context, string, []int, time.Duration) []model.Port { return nil },
	}
}

func TestHistoricalARPDoesNotKeepDisconnectedHostOnline(t *testing.T) {
	m := NewMerger(MergerOptions{})
	events := make(chan model.DeviceEvent, 10)
	ip := net.ParseIP("192.168.1.12")
	seen := time.Now().Add(-10 * time.Minute)
	m.handleUpdate(Update{Source: "arp", IP: ip, MAC: "aa:bb:cc:dd:ee:12", Time: seen}, events)
	w := &ActiveWorker{KnownIPs: m.KnownIPs, HostIPs: []net.IP{ip}, probes: silentProbes()}
	updates := make(chan Update, 10)
	for range 3 {
		w.SweepOnce(context.Background(), updates)
	}
	if len(updates) != 0 {
		t.Fatalf("failed probes published %d liveness updates", len(updates))
	}
	m.sweepStatus(context.Background(), time.Now(), events)
	dev := m.Snapshot()[0]
	if dev.Status != model.StatusOffline || !dev.LastSeen.Equal(seen) {
		t.Fatalf("disconnected host did not age out: %+v", dev)
	}
}

func TestKnownHostRequiresFreshProbeResponse(t *testing.T) {
	for _, signal := range []string{"icmp", "tcp", "nbns", "port"} {
		t.Run(signal, func(t *testing.T) {
			p := silentProbes()
			switch signal {
			case "icmp":
				p.ping = func(context.Context, string) (probe.PingResult, error) { return probe.PingResult{Alive: true}, nil }
			case "tcp":
				p.tcpAlive = func(context.Context, string) bool { return true }
			case "nbns":
				p.nbns = func(context.Context, string) string { return "WORKSTATION" }
			case "port":
				p.ports = func(context.Context, string, []int, time.Duration) []model.Port { return []model.Port{{Number: 443}} }
			}
			w := &ActiveWorker{probes: p}
			out := make(chan Update, 1)
			w.probeOne(context.Background(), net.ParseIP("192.168.1.12"), true, out)
			if len(out) != 1 || !(<-out).Alive {
				t.Fatal("fresh host response was not published")
			}
		})
	}
}

func TestActiveOneShotCompletesEntire22(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("192.168.0.0/22")
	p := silentProbes()
	p.tcpAlive = func(context.Context, string) bool { return true }
	w := &ActiveWorker{HostIPs: netiface.SubnetIPs(subnet), Once: true, WorkerCount: 32, probes: p}
	out := make(chan Update, len(w.HostIPs))
	if err := w.Run(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for len(out) > 0 {
		seen[(<-out).IP.String()] = true
	}
	if len(seen) != 1022 || !seen["192.168.3.254"] {
		t.Fatalf("incomplete sweep: %d addresses", len(seen))
	}
}

func TestCancelledEnrichmentDoesNotClearPorts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := silentProbes()
	p.tcpAlive = func(context.Context, string) bool { return true }
	p.ports = func(context.Context, string, []int, time.Duration) []model.Port { cancel(); return nil }
	out := make(chan Update, 1)
	(&ActiveWorker{probes: p}).probeOne(ctx, net.ParseIP("192.168.1.12"), true, out)
	if len(out) != 0 {
		t.Fatal("cancelled enrichment published a partial scan")
	}
}
