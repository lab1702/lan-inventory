// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/lab1702/lan-inventory/internal/netiface"
)

type fakeMDNSResolver struct {
	browse func(context.Context, string, string, chan<- *zeroconf.ServiceEntry) error
}

func (f *fakeMDNSResolver) Browse(ctx context.Context, service, domain string, entries chan<- *zeroconf.ServiceEntry) error {
	return f.browse(ctx, service, domain, entries)
}

func mdnsTestWorker() *MDNSWorker {
	return &MDNSWorker{Iface: &netiface.Info{
		Name: "test0", Subnet: &net.IPNet{IP: net.IPv4(192, 168, 1, 0), Mask: net.CIDRMask(24, 32)},
	}}
}

func mdnsTestIface(string) (*net.Interface, error) {
	return &net.Interface{Index: 7, Name: "test0"}, nil
}

func TestMDNSUsesOneScopedResolverPerServiceAndDrainsOnCancel(t *testing.T) {
	worker := mdnsTestWorker()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type start struct {
		id      int
		service string
		domain  string
	}
	started := make(chan start, len(commonServiceTypes))
	result := make(chan error, 1)
	var created, closed atomic.Int32
	go func() {
		result <- worker.run(ctx, make(chan Update), func(name string) (*net.Interface, error) {
			if name != "test0" {
				return nil, errors.New("wrong interface selected")
			}
			return mdnsTestIface(name)
		}, func(iface net.Interface) (mdnsResolver, error) {
			if iface.Index != 7 || iface.Name != "test0" {
				return nil, errors.New("resolver not bound to selected interface")
			}
			id := int(created.Add(1))
			return &fakeMDNSResolver{browse: func(ctx context.Context, service, domain string, entries chan<- *zeroconf.ServiceEntry) error {
				started <- start{id, service, domain}
				go func() {
					defer close(entries)
					entry := &zeroconf.ServiceEntry{AddrIPv4: []net.IP{net.IPv4(192, 168, 1, 25)}}
					entries <- entry
					<-ctx.Done()
					// Emulate zeroconf's unguarded entry sends, with enough
					// buffered responses to exceed the entry queue capacity.
					for i := 0; i < 40; i++ {
						entries <- entry
					}
					closed.Add(1)
				}()
				return nil
			}}, nil
		})
	}()
	ids := make(map[int]bool)
	services := make(map[string]bool)
	for range commonServiceTypes {
		select {
		case s := <-started:
			if ids[s.id] {
				t.Errorf("resolver %d reused for concurrent browses", s.id)
			}
			ids[s.id] = true
			services[s.service] = true
			if s.domain != "local." {
				t.Errorf("browse domain = %q", s.domain)
			}
		case err := <-result:
			t.Fatalf("Run stopped during setup: %v", err)
		case <-time.After(time.Second):
			t.Fatal("service browse did not start")
		}
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("mDNS did not drain entries and stop after cancellation")
	}
	if int(created.Load()) != len(commonServiceTypes) || closed.Load() != created.Load() {
		t.Errorf("created %d resolvers, stopped %d", created.Load(), closed.Load())
	}
	for _, service := range commonServiceTypes {
		if !services[service] {
			t.Errorf("missing service browse for %s", service)
		}
	}
}

func TestMDNSStartupFailuresStopEarlierResolvers(t *testing.T) {
	failure := errors.New("mDNS unavailable")
	for _, stage := range []string{"interface", "resolver", "browse"} {
		t.Run(stage, func(t *testing.T) {
			worker := mdnsTestWorker()
			var created, closed atomic.Int32
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- worker.run(ctx, make(chan Update), func(name string) (*net.Interface, error) {
					if stage == "interface" {
						return nil, failure
					}
					return mdnsTestIface(name)
				}, func(net.Interface) (mdnsResolver, error) {
					id := created.Add(1)
					if stage == "resolver" && id == 3 {
						return nil, failure
					}
					return &fakeMDNSResolver{browse: func(ctx context.Context, _, _ string, entries chan<- *zeroconf.ServiceEntry) error {
						go func() {
							<-ctx.Done()
							closed.Add(1)
							close(entries)
						}()
						if stage == "browse" && id == 3 {
							return failure
						}
						return nil
					}}, nil
				})
			}()
			select {
			case err := <-result:
				if !errors.Is(err, failure) {
					t.Errorf("Run error = %v, want %v", err, failure)
				}
			case <-time.After(time.Second):
				t.Fatal("initialization error did not stop mDNS worker")
			}
			wantClosed := int32(0)
			if stage == "resolver" {
				wantClosed = 2
			} else if stage == "browse" {
				wantClosed = 3
			}
			if closed.Load() != wantClosed {
				t.Errorf("closed %d browsers, want %d", closed.Load(), wantClosed)
			}
		})
	}
}

func TestMDNSEmptyBrowseExpirationRollsOver(t *testing.T) {
	worker := mdnsTestWorker()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	refresh := make(chan time.Time)
	started := make(chan string, len(commonServiceTypes))
	result := make(chan error, 1)
	go func() {
		result <- worker.runWithRefresh(ctx, make(chan Update), mdnsTestIface, func(net.Interface) (mdnsResolver, error) {
			return &fakeMDNSResolver{browse: func(_ context.Context, service, _ string, entries chan<- *zeroconf.ServiceEntry) error {
				started <- service
				// zeroconf closes an unanswered browse after its backoff
				// expires without returning an error from Browse.
				close(entries)
				return nil
			}}, nil
		}, refresh)
	}()
	for session := 0; session < 2; session++ {
		services := make(map[string]bool)
		for range commonServiceTypes {
			select {
			case service := <-started:
				services[service] = true
			case err := <-result:
				t.Fatalf("empty browse ended the worker: %v", err)
			case <-time.After(time.Second):
				t.Fatal("empty service was not browsed again")
			}
		}
		if len(services) != len(commonServiceTypes) {
			t.Errorf("session %d browsed %d distinct services", session, len(services))
		}
		if session == 0 {
			select {
			case refresh <- time.Now():
			case err := <-result:
				t.Fatalf("empty browse ended the worker: %v", err)
			case <-time.After(time.Second):
				t.Fatal("worker did not wait for scheduled refresh")
			}
		}
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("mDNS did not stop after cancellation")
	}
}

func TestMDNSRefreshesKnownInstancesWithNewMetadata(t *testing.T) {
	worker := mdnsTestWorker()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	refresh := make(chan time.Time)
	out := make(chan Update, len(commonServiceTypes))
	result := make(chan error, 1)
	var created, closed atomic.Int32
	go func() {
		result <- worker.runWithRefresh(ctx, out, mdnsTestIface, func(net.Interface) (mdnsResolver, error) {
			id := int(created.Add(1))
			session := (id-1)/len(commonServiceTypes) + 1
			if id == len(commonServiceTypes)+1 && int(closed.Load()) != len(commonServiceTypes) {
				return nil, errors.New("new session started before old resolvers stopped")
			}
			return &fakeMDNSResolver{browse: func(ctx context.Context, service, _ string, entries chan<- *zeroconf.ServiceEntry) error {
				go func() {
					entry := zeroconf.NewServiceEntry("Same instance", service, "local.")
					entry.AddrIPv4 = []net.IP{net.IPv4(192, 168, 1, 25)}
					entry.HostName = fmt.Sprintf("host%d.local.", session)
					entry.Port = 8000 + session
					entry.Text = []string{fmt.Sprintf("version=%d", session)}
					// A resolver sends each instance only once for its lifetime.
					entries <- entry
					<-ctx.Done()
					closed.Add(1)
					close(entries)
				}()
				return nil
			}}, nil
		}, refresh)
	}()
	for session := 1; session <= 2; session++ {
		services := make(map[string]bool)
		for range commonServiceTypes {
			select {
			case update := <-out:
				if update.Hostname != fmt.Sprintf("host%d.local", session) || len(update.Services) != 1 {
					t.Fatalf("session %d received stale or incomplete metadata: %+v", session, update)
				}
				service := update.Services[0]
				services[service.Type] = true
				if service.Name != "Same instance" || service.Port != 8000+session || service.TXT["version"] != fmt.Sprint(session) {
					t.Errorf("session %d service metadata: %+v", session, service)
				}
			case err := <-result:
				t.Fatalf("worker ended before refreshing known instance: %v", err)
			case <-time.After(time.Second):
				t.Fatal("known instance was not discovered again")
			}
		}
		if len(services) != len(commonServiceTypes) || !services["_apple-mobdev2._tcp"] || !services["_device-info._tcp"] {
			t.Errorf("session %d missing service types: %v", session, services)
		}
		if session == 1 {
			select {
			case refresh <- time.Now():
			case err := <-result:
				t.Fatalf("worker ended before refresh: %v", err)
			case <-time.After(time.Second):
				t.Fatal("worker did not wait for scheduled refresh")
			}
		}
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("mDNS did not stop after cancellation")
	}
	if int(created.Load()) != 2*len(commonServiceTypes) || closed.Load() != created.Load() {
		t.Errorf("created %d resolvers, stopped %d", created.Load(), closed.Load())
	}
}

func TestMDNSFiltersAddressesToSelectedSubnet(t *testing.T) {
	worker := mdnsTestWorker()
	entries := make(chan *zeroconf.ServiceEntry, 5)
	entries <- &zeroconf.ServiceEntry{AddrIPv4: []net.IP{net.IPv4(10, 0, 0, 2)}}
	entries <- &zeroconf.ServiceEntry{AddrIPv6: []net.IP{net.ParseIP("fe80::1")}}
	entries <- nil
	inside := net.IPv4(192, 168, 1, 23)
	entry := zeroconf.NewServiceEntry("Kitchen", "_http._tcp", "local.")
	entry.HostName = "kitchen.local."
	entry.Port = 8080
	entry.Text = []string{"PATH=/status"}
	entry.AddrIPv4 = []net.IP{net.IPv4(10, 0, 0, 3), inside}
	entries <- entry
	close(entries)
	out := make(chan Update, 5)
	worker.consume(context.Background(), "_http._tcp", entries, out)
	if len(out) != 1 {
		t.Fatalf("got %d updates, want only the in-subnet service", len(out))
	}
	update := <-out
	if !update.IP.Equal(inside) || update.Hostname != "kitchen.local" || update.Source != "mdns" {
		t.Errorf("unexpected update: %+v", update)
	}
	if len(update.Services) != 1 || update.Services[0].Port != 8080 || update.Services[0].TXT["path"] != "/status" {
		t.Errorf("service metadata lost: %+v", update.Services)
	}
	inside[len(inside)-1] = 99
	if update.IP.String() != "192.168.1.23" {
		t.Error("update IP aliases resolver entry memory")
	}
}
