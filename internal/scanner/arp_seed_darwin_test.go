// SPDX-License-Identifier: GPL-2.0-or-later

//go:build darwin

package scanner

import (
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/route"
)

func mustCIDRDarwin(t *testing.T, s string) *net.IPNet {
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
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}},
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), now)
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
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}},
		{IfaceIndex: 9, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 10)) {
		t.Fatalf("iface filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersOutsideSubnet(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}},
		{IfaceIndex: 7, IP: net.IPv4(10, 0, 0, 5), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 10)) {
		t.Fatalf("subnet filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersZeroMAC(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0, 0, 0, 0, 0, 0}},
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 11)) {
		t.Fatalf("zero-MAC filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersShortMAC(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d}}, // 3 bytes
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 11)) {
		t.Fatalf("short-MAC filter failed: %+v", got)
	}
}

func TestRowsToUpdates_PopulatesVendor(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 {
		t.Fatalf("want 1 update, got %d", len(got))
	}
	if got[0].Vendor == "" {
		t.Error("expected non-empty Vendor for known OUI 08:3a:8d")
	}
}

func TestExtractARPRows_ParsesValidEntry(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 4,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{192, 168, 1, 10}},
				&route.LinkAddr{Index: 4, Addr: []byte{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}},
			},
		},
	}
	rows := extractARPRows(msgs)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].IfaceIndex != 4 {
		t.Errorf("IfaceIndex = %d, want 4", rows[0].IfaceIndex)
	}
	if !rows[0].IP.Equal(net.IPv4(192, 168, 1, 10)) {
		t.Errorf("IP = %v, want 192.168.1.10", rows[0].IP)
	}
	if rows[0].MAC.String() != "08:3a:8d:8e:3e:f0" {
		t.Errorf("MAC = %v", rows[0].MAC)
	}
}

func TestExtractARPRows_FiltersShortLinkAddr(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 4,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{192, 168, 1, 10}},
				&route.LinkAddr{Index: 4, Addr: []byte{0x08}}, // 1 byte ⇒ filtered
			},
		},
	}
	if rows := extractARPRows(msgs); len(rows) != 0 {
		t.Errorf("expected short-MAC LinkAddr filtered, got %d rows", len(rows))
	}
}

func TestExtractARPRows_FiltersNonRouteMessage(t *testing.T) {
	// A message that is not a *route.RouteMessage (e.g. interface
	// message) should be skipped.
	msgs := []route.Message{
		&route.InterfaceMessage{Index: 4},
	}
	if rows := extractARPRows(msgs); len(rows) != 0 {
		t.Errorf("expected non-RouteMessage filtered, got %d rows", len(rows))
	}
}
