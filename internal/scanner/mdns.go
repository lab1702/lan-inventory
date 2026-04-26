// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"

	"github.com/lab1702/lan-inventory/internal/model"
)

// MDNSWorker browses for mDNS services on the given interface and emits an
// Update for each discovered instance.
type MDNSWorker struct {
	IfaceName string
}

// commonServiceTypes is the seed list we actively browse for. zeroconf doesn't
// support a single "browse everything" query well, so we enumerate a handful
// of widely-deployed services. Additional services that announce themselves
// via gratuitous packets will still be observed.
var commonServiceTypes = []string{
	"_http._tcp",
	"_https._tcp",
	"_ssh._tcp",
	"_airplay._tcp",
	"_googlecast._tcp",
	"_printer._tcp",
	"_ipp._tcp",
	"_smb._tcp",
	"_workstation._tcp",
}

func (w *MDNSWorker) Run(ctx context.Context, out chan<- Update) error {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return fmt.Errorf("zeroconf resolver: %w", err)
	}

	for _, svc := range commonServiceTypes {
		svc := svc
		entries := make(chan *zeroconf.ServiceEntry, 16)
		go w.consume(ctx, svc, entries, out)
		go func() {
			if err := resolver.Browse(ctx, svc, "local.", entries); err != nil {
				return
			}
		}()
	}
	<-ctx.Done()
	return nil
}

func (w *MDNSWorker) consume(ctx context.Context, svc string, entries <-chan *zeroconf.ServiceEntry, out chan<- Update) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-entries:
			if !ok {
				return
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
				Hostname: trimDot(e.HostName),
				Services: []model.ServiceInst{
					{Type: svc, Name: e.Instance, Port: e.Port, TXT: txt},
				},
			}
			if len(e.AddrIPv4) > 0 {
				update.IP = pickFirstIP(e.AddrIPv4)
			}
			select {
			case out <- update:
			case <-ctx.Done():
				return
			}
		}
	}
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func pickFirstIP(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	return nil
}