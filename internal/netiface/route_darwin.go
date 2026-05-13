// SPDX-License-Identifier: GPL-2.0-or-later

//go:build darwin

// Package netiface — Darwin route resolver. Dumps the IPv4 routing
// table via sysctl (NET_RT_DUMP) and parses it with
// golang.org/x/net/route. The default route is the entry whose
// destination is the IPv4 unspecified address (0.0.0.0) with a missing
// or all-zero netmask.
package netiface

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/route"
)

// BSD RTAX_* indices into route.RouteMessage.Addrs.
const (
	rtaxDst     = 0
	rtaxGateway = 1
	rtaxNetmask = 2
)

// routeCandidate is one default-route entry extracted from a parsed
// route message. Kept as a thin struct so pickDefaultRouteCandidate is
// pure and unit-testable without making real syscalls.
type routeCandidate struct {
	IfaceIndex int
	Gateway    net.IP
}

// defaultRouteInterface dumps the IPv4 routing table via sysctl and
// returns the interface + gateway for the system's default route.
func defaultRouteInterface() (*net.Interface, net.IP, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("FetchRIB(NET_RT_DUMP): %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, nil, fmt.Errorf("ParseRIB(NET_RT_DUMP): %w", err)
	}
	cands := defaultRouteCandidates(msgs)
	best, err := pickDefaultRouteCandidate(cands)
	if err != nil {
		return nil, nil, err
	}
	iface, err := net.InterfaceByIndex(best.IfaceIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("InterfaceByIndex(%d): %w", best.IfaceIndex, err)
	}
	return iface, best.Gateway, nil
}

// defaultRouteCandidates extracts default-route entries from parsed
// route messages. A default route has destination 0.0.0.0 and either a
// missing netmask or an all-zero netmask.
func defaultRouteCandidates(msgs []route.Message) []routeCandidate {
	var cands []routeCandidate
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		if len(rm.Addrs) <= rtaxGateway {
			continue
		}
		dst, ok := rm.Addrs[rtaxDst].(*route.Inet4Addr)
		if !ok {
			continue
		}
		if dst.IP != ([4]byte{0, 0, 0, 0}) {
			continue
		}
		// Netmask absent or all-zero ⇒ default route.
		if len(rm.Addrs) > rtaxNetmask {
			if mask, ok := rm.Addrs[rtaxNetmask].(*route.Inet4Addr); ok {
				if mask.IP != ([4]byte{0, 0, 0, 0}) {
					continue
				}
			}
		}
		gw, ok := rm.Addrs[rtaxGateway].(*route.Inet4Addr)
		if !ok {
			continue
		}
		cands = append(cands, routeCandidate{
			IfaceIndex: rm.Index,
			Gateway:    net.IPv4(gw.IP[0], gw.IP[1], gw.IP[2], gw.IP[3]),
		})
	}
	return cands
}

// pickDefaultRouteCandidate picks the first candidate, which is the
// kernel's preferred default route (matches `netstat -rn` ordering on
// macOS).
func pickDefaultRouteCandidate(cands []routeCandidate) (*routeCandidate, error) {
	if len(cands) == 0 {
		return nil, errors.New("no default route — cannot determine which subnet to scan")
	}
	return &cands[0], nil
}
