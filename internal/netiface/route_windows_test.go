// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package netiface

import (
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestPickBestGatewayCandidate_LowestMetricWins(t *testing.T) {
	cands := []gatewayCandidate{
		{IfaceIndex: 5, Gateway: net.IPv4(192, 168, 1, 1), Metric: 25},
		{IfaceIndex: 7, Gateway: net.IPv4(10, 0, 0, 1), Metric: 15},
		{IfaceIndex: 9, Gateway: net.IPv4(172, 16, 0, 1), Metric: 40},
	}
	best, err := pickBestGatewayCandidate(cands)
	if err != nil {
		t.Fatalf("pickBestGatewayCandidate: %v", err)
	}
	if best.IfaceIndex != 7 {
		t.Errorf("IfaceIndex = %d, want 7", best.IfaceIndex)
	}
	if !best.Gateway.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Errorf("Gateway = %v, want 10.0.0.1", best.Gateway)
	}
}

func TestPickBestGatewayCandidate_EmptyReturnsError(t *testing.T) {
	if _, err := pickBestGatewayCandidate(nil); err == nil {
		t.Errorf("expected error on empty candidate list")
	}
}

func TestPickBestGatewayCandidate_StableOnTies(t *testing.T) {
	cands := []gatewayCandidate{
		{IfaceIndex: 3, Gateway: net.IPv4(192, 168, 1, 1), Metric: 20},
		{IfaceIndex: 4, Gateway: net.IPv4(10, 0, 0, 1), Metric: 20},
	}
	best, err := pickBestGatewayCandidate(cands)
	if err != nil {
		t.Fatalf("pickBestGatewayCandidate: %v", err)
	}
	if best.IfaceIndex != 3 {
		t.Errorf("IfaceIndex = %d, want 3 (first wins on tie)", best.IfaceIndex)
	}
}

func testIPv4Route(index, metric uint32, gateway [4]byte) windows.MibIpForwardRow2 {
	route := windows.MibIpForwardRow2{
		InterfaceIndex: index,
		Metric:         metric,
		ValidLifetime:  ^uint32(0),
	}
	prefix := (*windows.RawSockaddrInet4)(unsafe.Pointer(&route.DestinationPrefix.Prefix))
	prefix.Family = windows.AF_INET
	nextHop := (*windows.RawSockaddrInet4)(unsafe.Pointer(&route.NextHop))
	nextHop.Family = windows.AF_INET
	nextHop.Addr = gateway
	return route
}

func TestGatewayCandidatesUseRouteAndInterfaceMetric(t *testing.T) {
	second := &windows.IpAdapterAddresses{IfIndex: 7, Ipv4Metric: 25, OperStatus: windows.IfOperStatusUp}
	first := &windows.IpAdapterAddresses{IfIndex: 5, Ipv4Metric: 5, OperStatus: windows.IfOperStatusUp, Next: second}
	routes := []windows.MibIpForwardRow2{
		testIPv4Route(5, 100, [4]byte{192, 168, 1, 1}),
		testIPv4Route(7, 5, [4]byte{10, 0, 0, 2}),
	}
	best, err := pickBestGatewayCandidate(gatewayCandidatesFromRoutes(routes, first))
	if err != nil {
		t.Fatal(err)
	}
	if best.IfaceIndex != 7 || best.Metric != 30 || !best.Gateway.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("got %+v; want interface 7, total metric 30, route gateway 10.0.0.2", best)
	}
	// Multiple defaults on one interface must use the chosen route's gateway.
	routes = append(routes, testIPv4Route(7, 1, [4]byte{10, 0, 0, 3}))
	best, err = pickBestGatewayCandidate(gatewayCandidatesFromRoutes(routes, first))
	if err != nil || best.Metric != 26 || !best.Gateway.Equal(net.IPv4(10, 0, 0, 3)) {
		t.Fatalf("got %+v, %v; want lower-metric route via 10.0.0.3", best, err)
	}
}

func TestGatewayCandidatesFilterNonDefaultAndInactiveRoutes(t *testing.T) {
	adapter := &windows.IpAdapterAddresses{IfIndex: 5, Ipv4Metric: 5, OperStatus: windows.IfOperStatusUp}
	for _, tt := range []struct {
		name   string
		mutate func(*windows.MibIpForwardRow2, *windows.IpAdapterAddresses)
	}{
		{"subnet route", func(r *windows.MibIpForwardRow2, _ *windows.IpAdapterAddresses) {
			r.DestinationPrefix.PrefixLength = 24
		}},
		{"nonzero destination", func(r *windows.MibIpForwardRow2, _ *windows.IpAdapterAddresses) {
			(*windows.RawSockaddrInet4)(unsafe.Pointer(&r.DestinationPrefix.Prefix)).Addr = [4]byte{10, 0, 0, 0}
		}},
		{"IPv6 default", func(r *windows.MibIpForwardRow2, _ *windows.IpAdapterAddresses) {
			r.DestinationPrefix.Prefix.Family = windows.AF_INET6
		}},
		{"non-IPv4 next hop", func(r *windows.MibIpForwardRow2, _ *windows.IpAdapterAddresses) {
			r.NextHop.Family = windows.AF_INET6
		}},
		{"loopback", func(r *windows.MibIpForwardRow2, _ *windows.IpAdapterAddresses) { r.Loopback = 1 }},
		{"expired", func(r *windows.MibIpForwardRow2, _ *windows.IpAdapterAddresses) { r.ValidLifetime = 0 }},
		{"missing adapter", func(r *windows.MibIpForwardRow2, _ *windows.IpAdapterAddresses) { r.InterfaceIndex = 7 }},
		{"down adapter", func(_ *windows.MibIpForwardRow2, a *windows.IpAdapterAddresses) {
			a.OperStatus = windows.IfOperStatusDown
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			route := testIPv4Route(5, 1, [4]byte{192, 168, 1, 1})
			copyAdapter := *adapter
			tt.mutate(&route, &copyAdapter)
			if got := gatewayCandidatesFromRoutes([]windows.MibIpForwardRow2{route}, &copyAdapter); len(got) != 0 {
				t.Fatalf("unexpected candidates: %+v", got)
			}
		})
	}
	// A gateway in adapter configuration is insufficient without a route.
	adapter.FirstGatewayAddress = &windows.IpAdapterGatewayAddress{}
	if got := gatewayCandidatesFromRoutes(nil, adapter); len(got) != 0 {
		t.Fatalf("adapter without a default route produced candidates: %+v", got)
	}
}

func TestGatewayCandidatesMetricDoesNotOverflow(t *testing.T) {
	adapter := &windows.IpAdapterAddresses{IfIndex: 5, Ipv4Metric: ^uint32(0), OperStatus: windows.IfOperStatusUp}
	routes := []windows.MibIpForwardRow2{testIPv4Route(5, 10, [4]byte{})}
	cands := gatewayCandidatesFromRoutes(routes, adapter)
	if len(cands) != 1 || cands[0].Metric != uint64(^uint32(0))+10 {
		t.Fatalf("effective metric overflowed: %+v", cands)
	}
	// An on-link default route has an unspecified next hop and remains valid.
	if !cands[0].Gateway.IsUnspecified() {
		t.Fatalf("on-link gateway = %v, want unspecified", cands[0].Gateway)
	}
}
