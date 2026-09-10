// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

// Package netiface — Windows route resolver. We pick an operational
// adapter with an IPv4 default route, using the route plus interface metric.
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
	Metric     uint64
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

// defaultRouteInterface returns the operational IPv4 default-route interface
// with the lowest effective metric and that route's next-hop gateway.
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

// collectGatewayCandidates joins actual IPv4 routes from GetIpForwardTable2
// with adapter state and metrics from GetAdaptersAddresses. A configured
// adapter gateway alone does not establish that a default route exists.
func collectGatewayCandidates() ([]gatewayCandidate, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST |
		windows.GAA_FLAG_SKIP_DNS_SERVER

	// Start with the recommended buffer size and tolerate adapter changes
	// that increase the required allocation between calls.
	bufLen := uint32(15 * 1024)
	var first *windows.IpAdapterAddresses
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, bufLen)
		first = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err = windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, first, &bufLen)
		if err != windows.ERROR_BUFFER_OVERFLOW {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	return gatewayCandidatesFromRoutes(table.Rows(), first), nil
}

func gatewayCandidatesFromRoutes(routes []windows.MibIpForwardRow2, first *windows.IpAdapterAddresses) []gatewayCandidate {
	metrics := make(map[uint32]uint32)
	for aa := first; aa != nil; aa = aa.Next {
		if aa.OperStatus == windows.IfOperStatusUp {
			metrics[aa.IfIndex] = aa.Ipv4Metric
		}
	}
	var cands []gatewayCandidate
	for _, route := range routes {
		metric, up := metrics[route.InterfaceIndex]
		if !up || route.Loopback != 0 || route.ValidLifetime == 0 ||
			route.DestinationPrefix.PrefixLength != 0 || route.DestinationPrefix.Prefix.Family != windows.AF_INET ||
			route.NextHop.Family != windows.AF_INET {
			continue
		}
		prefix := (*windows.RawSockaddrInet4)(unsafe.Pointer(&route.DestinationPrefix.Prefix))
		if prefix.Addr != [4]byte{} {
			continue
		}
		nextHop := (*windows.RawSockaddrInet4)(unsafe.Pointer(&route.NextHop))
		cands = append(cands, gatewayCandidate{
			IfaceIndex: route.InterfaceIndex,
			Gateway:    net.IPv4(nextHop.Addr[0], nextHop.Addr[1], nextHop.Addr[2], nextHop.Addr[3]),
			// Windows ranks routes using the sum, not either metric alone.
			Metric: uint64(metric) + uint64(route.Metric),
		})
	}
	return cands
}
