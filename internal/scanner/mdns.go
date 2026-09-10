// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/netiface"
)

// MDNSWorker browses for mDNS services on the given interface and emits an
// Update for each discovered instance in the selected IPv4 subnet.
type MDNSWorker struct {
	Iface *netiface.Info
}

// commonServiceTypes is the seed list we actively browse for. zeroconf doesn't
// support a single "browse everything" query well, so we enumerate a handful
// of widely-deployed services.
var commonServiceTypes = []string{
	"_http._tcp",
	"_https._tcp",
	"_ssh._tcp",
	"_airplay._tcp",
	"_apple-mobdev2._tcp",
	"_device-info._tcp",
	"_googlecast._tcp",
	"_printer._tcp",
	"_ipp._tcp",
	"_smb._tcp",
	"_workstation._tcp",
}

// zeroconf suppresses repeat instances for a browse's entire lifetime. Start
// fresh sessions so announcements keep devices online and update their metadata.
const mdnsRefreshInterval = 30 * time.Second

type mdnsResolver interface {
	Browse(context.Context, string, string, chan<- *zeroconf.ServiceEntry) error
}

func newMDNSResolver(iface net.Interface) (mdnsResolver, error) {
	return zeroconf.NewResolver(
		zeroconf.SelectIfaces([]net.Interface{iface}),
		zeroconf.SelectIPTraffic(zeroconf.IPv4),
	)
}

func (w *MDNSWorker) Run(ctx context.Context, out chan<- Update) error {
	return w.run(ctx, out, net.InterfaceByName, newMDNSResolver)
}

func (w *MDNSWorker) run(ctx context.Context, out chan<- Update, lookupIface func(string) (*net.Interface, error), newResolver func(net.Interface) (mdnsResolver, error)) error {
	refresh := time.NewTicker(mdnsRefreshInterval)
	defer refresh.Stop()
	return w.runWithRefresh(ctx, out, lookupIface, newResolver, refresh.C)
}

func (w *MDNSWorker) runWithRefresh(ctx context.Context, out chan<- Update, lookupIface func(string) (*net.Interface, error), newResolver func(net.Interface) (mdnsResolver, error), refresh <-chan time.Time) error {
	if w.Iface == nil || w.Iface.Subnet == nil {
		return fmt.Errorf("mDNS interface and subnet are required")
	}
	if ctx.Err() != nil {
		return nil
	}
	iface, err := lookupIface(w.Iface.Name)
	if err != nil {
		return fmt.Errorf("mDNS interface %s: %w", w.Iface.Name, err)
	}

	for ctx.Err() == nil {
		if err := w.browseSession(ctx, out, *iface, newResolver, refresh); err != nil {
			return err
		}
	}
	return nil
}

func (w *MDNSWorker) browseSession(ctx context.Context, out chan<- Update, iface net.Interface, newResolver func(net.Interface) (mdnsResolver, error), refresh <-chan time.Time) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	for _, svc := range commonServiceTypes {
		if ctx.Err() != nil {
			return nil
		}
		// Each Browse starts readers on its resolver's sockets. Sharing one
		// resolver would let competing readers discard other services' replies.
		resolver, err := newResolver(iface)
		if err != nil {
			return fmt.Errorf("zeroconf resolver for %s: %w", svc, err)
		}
		entries := make(chan *zeroconf.ServiceEntry, 16)
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.consume(ctx, svc, entries, out)
		}()
		// Browse returns after initialization; its mainloop closes entries on
		// cancellation, including when the initial query fails.
		if err := resolver.Browse(ctx, svc, "local.", entries); err != nil {
			return fmt.Errorf("mDNS browse for %s: %w", svc, err)
		}
	}
	select {
	case <-ctx.Done():
	case <-refresh:
	}
	// An empty browse can expire inside zeroconf and close entries without an
	// error. The next scheduled session retries it along with discovered types.
	return nil
}

func (w *MDNSWorker) consume(ctx context.Context, svc string, entries <-chan *zeroconf.ServiceEntry, out chan<- Update) {
	// zeroconf sends entries without selecting on its context. Continue
	// draining after cancellation until its mainloop closes the channel, so a
	// full entry queue cannot prevent resolver shutdown.
	for e := range entries {
		if ctx.Err() != nil || e == nil {
			continue
		}
		ip := w.scopedIP(e.AddrIPv4)
		if ip == nil {
			continue
		}
		txt := map[string]string{}
		for _, kv := range e.Text {
			if i := strings.IndexByte(kv, '='); i > 0 {
				txt[strings.ToLower(kv[:i])] = kv[i+1:]
			}
		}
		update := Update{
			Source:   "mdns",
			Time:     time.Now(),
			IP:       ip,
			Hostname: trimDot(e.HostName),
			Services: []model.ServiceInst{
				{Type: svc, Name: e.Instance, Port: e.Port, TXT: txt},
			},
		}
		select {
		case out <- update:
		case <-ctx.Done():
		}
	}
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func (w *MDNSWorker) scopedIP(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsUnspecified() && w.Iface.Subnet.Contains(ip4) {
			return append(net.IP(nil), ip4...)
		}
	}
	return nil
}
