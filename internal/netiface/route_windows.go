// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

// Package netiface — Windows route resolver. We pick the operational
// adapter with the lowest IPv4 metric whose adapter advertises a
// non-empty gateway list. That matches the Linux semantics of "default
// route with the lowest metric".
package netiface

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// gatewayCandidate is one row of the working set used to pick the
// default-route adapter. Extracted so the selection logic is pure and
// unit-testable without making real syscalls.
type gatewayCandidate struct {
	IfaceIndex uint32
	Gateway    net.IP
	Metric     uint32
}

// pickBestGatewayCandidate returns the candidate with the lowest Metric.
// On ties, the first one in the input slice wins.
func pickBestGatewayCandidate(cands []gatewayCandidate) (*gatewayCandidate, error) {
	if len(cands) == 0 {
		return nil, errors.New("no default route — cannot determine which subnet to scan")
	}
	best := &cands[0]
	for i := 1; i < len(cands); i++ {
		if cands[i].Metric < best.Metric {
			best = &cands[i]
		}
	}
	return best, nil
}

// defaultRouteInterface enumerates Windows adapters via GetAdaptersAddresses,
// collects every operational IPv4 adapter that has at least one gateway,
// and returns the one with the lowest Ipv4Metric.
func defaultRouteInterface() (*net.Interface, net.IP, error) {
	cands, err := collectGatewayCandidates()
	if err != nil {
		return nil, nil, err
	}
	best, err := pickBestGatewayCandidate(cands)
	if err != nil {
		return nil, nil, err
	}
	iface, err := net.InterfaceByIndex(int(best.IfaceIndex))
	if err != nil {
		return nil, nil, fmt.Errorf("net.InterfaceByIndex(%d): %w", best.IfaceIndex, err)
	}
	return iface, best.Gateway, nil
}

// collectGatewayCandidates calls GetAdaptersAddresses with
// GAA_FLAG_INCLUDE_GATEWAYS and returns one candidate per operational
// adapter that has at least one IPv4 gateway. The adapter's Ipv4Metric is
// captured as Metric so pickBestGatewayCandidate can choose the default
// route.
func collectGatewayCandidates() ([]gatewayCandidate, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS |
		windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST |
		windows.GAA_FLAG_SKIP_DNS_SERVER

	// Probe size, then allocate.
	var bufLen uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, nil, &bufLen)
	if err != windows.ERROR_BUFFER_OVERFLOW {
		return nil, fmt.Errorf("GetAdaptersAddresses (size probe): %w", err)
	}
	buf := make([]byte, bufLen)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &bufLen); err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	var cands []gatewayCandidate
	for aa := first; aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp {
			continue
		}
		gw := firstIPv4Gateway(aa)
		if gw == nil {
			continue
		}
		cands = append(cands, gatewayCandidate{
			IfaceIndex: aa.IfIndex,
			Gateway:    gw,
			Metric:     aa.Ipv4Metric,
		})
	}
	return cands, nil
}

// firstIPv4Gateway returns the first IPv4 address found in the adapter's
// linked list of gateway addresses, or nil if there is none.
func firstIPv4Gateway(aa *windows.IpAdapterAddresses) net.IP {
	for ga := aa.FirstGatewayAddress; ga != nil; ga = ga.Next {
		ip := ga.Address.IP()
		if ip4 := ip.To4(); ip4 != nil {
			return ip4
		}
	}
	return nil
}
