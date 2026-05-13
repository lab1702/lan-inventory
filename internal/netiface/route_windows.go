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

// collectGatewayCandidates is the syscall-touching half of the resolver.
// Implemented in Task 5.
func collectGatewayCandidates() ([]gatewayCandidate, error) {
	return nil, errors.New("collectGatewayCandidates: not yet implemented")
}
