// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package netiface

import (
	"net"
	"testing"
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
