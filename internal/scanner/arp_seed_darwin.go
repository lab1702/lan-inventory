// SPDX-License-Identifier: GPL-2.0-or-later

//go:build darwin

package scanner

import (
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/route"

	"github.com/lab1702/lan-inventory/internal/oui"
)

// BSD sysctl + route-flag constants. Values match
// golang.org/x/sys/unix.{NET_RT_FLAGS,RTF_LLINFO} on darwin; held as
// private literals here to avoid pulling x/sys/unix just for two
// integers.
const (
	netRTFlags = 2
	rtfLLINFO  = 0x400
)

// arpRow is the platform-agnostic projection of a BSD ARP-cache entry.
// rowsToUpdates operates on this so unit tests do not need to make
// syscalls.
type arpRow struct {
	IfaceIndex int
	IP         net.IP
	MAC        net.HardwareAddr
}

// rowsToUpdates filters arpRows by interface index and subnet
// membership, drops zero-length / all-zero MACs, and emits one Update
// per survivor. Shape matches parseProcNetARP and the Windows
// rowsToUpdates exactly: Source "arp-seed", lowercase MAC, vendor
// populated from the bundled OUI table.
func rowsToUpdates(rows []arpRow, ifaceIndex int, subnet *net.IPNet, now time.Time) []Update {
	var out []Update
	for _, r := range rows {
		if r.IfaceIndex != ifaceIndex {
			continue
		}
		if len(r.MAC) != 6 {
			continue
		}
		if isZeroMAC(r.MAC) {
			continue
		}
		ip4 := r.IP.To4()
		if ip4 == nil || !subnet.Contains(ip4) {
			continue
		}
		mac := strings.ToLower(r.MAC.String())
		out = append(out, Update{
			Source: "arp-seed",
			Time:   now,
			MAC:    mac,
			IP:     ip4,
			Vendor: oui.Lookup(mac),
		})
	}
	return out
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

// extractARPRows pulls per-neighbor entries out of parsed route
// messages. ARP-cache entries arrive as *route.RouteMessage with
// Addrs[0] = neighbor IPv4 address and Addrs[1] = LinkAddr carrying
// the MAC.
func extractARPRows(msgs []route.Message) []arpRow {
	var out []arpRow
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		if len(rm.Addrs) < 2 {
			continue
		}
		dst, ok := rm.Addrs[0].(*route.Inet4Addr)
		if !ok {
			continue
		}
		la, ok := rm.Addrs[1].(*route.LinkAddr)
		if !ok {
			continue
		}
		if len(la.Addr) != 6 {
			continue
		}
		out = append(out, arpRow{
			IfaceIndex: rm.Index,
			IP:         net.IPv4(dst.IP[0], dst.IP[1], dst.IP[2], dst.IP[3]),
			MAC:        net.HardwareAddr(la.Addr),
		})
	}
	return out
}

// SeedFromKernelARP reads the IPv4 ARP cache via
// sysctl(NET_RT_FLAGS, RTF_LLINFO) and emits one Update per neighbor
// on the chosen interface within subnet. Best-effort: returns nil on
// any failure.
func SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update {
	if ifaceName == "" || subnet == nil {
		return nil
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBType(netRTFlags), rtfLLINFO)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	return rowsToUpdates(extractARPRows(msgs), iface.Index, subnet, time.Now())
}
