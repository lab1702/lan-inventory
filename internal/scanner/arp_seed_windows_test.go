// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package scanner

import (
	"net"
	"strings"
	"testing"
	"time"
)

func mustCIDRWin(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad CIDR %q: %v", s, err)
	}
	return n
}

func TestRowsToUpdates_BasicHappyPath(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}, Reachable: true},
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), now)
	if len(got) != 2 {
		t.Fatalf("want 2 updates, got %d", len(got))
	}
	for _, u := range got {
		if u.Source != "arp-seed" {
			t.Errorf("Source = %q, want arp-seed", u.Source)
		}
		if !u.Time.Equal(now) {
			t.Errorf("Time = %v, want %v", u.Time, now)
		}
		if u.MAC != strings.ToLower(u.MAC) {
			t.Errorf("MAC %q not lowercase", u.MAC)
		}
	}
	if got[0].MAC != "08:3a:8d:8e:3e:f0" {
		t.Errorf("row 0 MAC mismatch: %q", got[0].MAC)
	}
}

func TestRowsToUpdates_FiltersWrongIface(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}, Reachable: true},
		{IfaceIndex: 9, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 10)) {
		t.Fatalf("iface filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersOutsideSubnet(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}, Reachable: true},
		{IfaceIndex: 7, IP: net.IPv4(10, 0, 0, 5), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 10)) {
		t.Fatalf("subnet filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersUnreachable(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}, Reachable: false},
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 11)) {
		t.Fatalf("reachable filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersZeroMAC(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0, 0, 0, 0, 0, 0}, Reachable: true},
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 11)) {
		t.Fatalf("zero-MAC filter failed: %+v", got)
	}
}

func TestRowsToUpdates_PopulatesVendor(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 {
		t.Fatalf("want 1 update, got %d", len(got))
	}
	if got[0].Vendor == "" {
		t.Error("expected non-empty Vendor for known OUI 08:3a:8d")
	}
}
