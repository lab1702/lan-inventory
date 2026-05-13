// SPDX-License-Identifier: GPL-2.0-or-later

//go:build darwin

package netiface

import (
	"net"
	"testing"

	"golang.org/x/net/route"
)

func TestDefaultRouteCandidates_ExtractsDefault(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 4,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},     // dst
				&route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}}, // gateway
				&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},     // netmask
			},
		},
	}
	got := defaultRouteCandidates(msgs)
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
	if got[0].IfaceIndex != 4 {
		t.Errorf("IfaceIndex = %d, want 4", got[0].IfaceIndex)
	}
	if !got[0].Gateway.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("Gateway = %v, want 192.168.1.1", got[0].Gateway)
	}
}

func TestDefaultRouteCandidates_FiltersNonDefault(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 4,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{10, 0, 0, 0}}, // dst non-zero
				&route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}},
				&route.Inet4Addr{IP: [4]byte{255, 0, 0, 0}},
			},
		},
	}
	if got := defaultRouteCandidates(msgs); len(got) != 0 {
		t.Errorf("non-default route should be filtered, got %d candidates", len(got))
	}
}

func TestDefaultRouteCandidates_NetmaskAbsentTreatedAsDefault(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 5,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},
				&route.Inet4Addr{IP: [4]byte{10, 0, 0, 1}},
				// netmask omitted entirely
			},
		},
	}
	if got := defaultRouteCandidates(msgs); len(got) != 1 {
		t.Errorf("absent netmask should count as default, got %d candidates", len(got))
	}
}

func TestDefaultRouteCandidates_NonZeroNetmaskFiltered(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 4,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},
				&route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}},
				&route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}}, // /24, not default
			},
		},
	}
	if got := defaultRouteCandidates(msgs); len(got) != 0 {
		t.Errorf("non-zero netmask should be filtered, got %d candidates", len(got))
	}
}

func TestDefaultRouteCandidates_IPv6Filtered(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 6,
			Addrs: []route.Addr{
				&route.Inet6Addr{IP: [16]byte{}},
				&route.Inet6Addr{IP: [16]byte{}},
			},
		},
	}
	if got := defaultRouteCandidates(msgs); len(got) != 0 {
		t.Errorf("IPv6 route should be filtered, got %d candidates", len(got))
	}
}

func TestPickDefaultRouteCandidate_FirstWins(t *testing.T) {
	cands := []routeCandidate{
		{IfaceIndex: 5, Gateway: net.IPv4(192, 168, 1, 1)},
		{IfaceIndex: 7, Gateway: net.IPv4(10, 0, 0, 1)},
	}
	best, err := pickDefaultRouteCandidate(cands)
	if err != nil {
		t.Fatalf("pickDefaultRouteCandidate: %v", err)
	}
	if best.IfaceIndex != 5 {
		t.Errorf("IfaceIndex = %d, want 5 (first wins)", best.IfaceIndex)
	}
}

func TestPickDefaultRouteCandidate_EmptyReturnsError(t *testing.T) {
	if _, err := pickDefaultRouteCandidate(nil); err == nil {
		t.Errorf("expected error on empty candidate list")
	}
}
