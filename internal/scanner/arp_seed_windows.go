// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package scanner

import (
	"net"
	"strings"
	"time"

	"github.com/lab1702/lan-inventory/internal/oui"
)

// arpRow is the platform-agnostic projection of a Win32 ARP-table row.
// The pure rowsToUpdates helper operates on this so unit tests do not
// need to make syscalls.
type arpRow struct {
	IfaceIndex uint32
	IP         net.IP
	MAC        net.HardwareAddr
	// Reachable is true for entries whose Win32 state is one of
	// Reachable / Stale / Delay / Probe — i.e., the kernel has a real
	// MAC for this neighbor. False for Unreachable / Incomplete.
	Reachable bool
}

// rowsToUpdates filters arpRows by interface index and subnet membership,
// drops zero-MAC and unreachable entries, and emits one Update per
// survivor. The emitted shape is identical to parseProcNetARP's output on
// Linux: Source "arp-seed", lowercase MAC, vendor populated from the
// bundled OUI table.
func rowsToUpdates(rows []arpRow, ifaceIndex uint32, subnet *net.IPNet, now time.Time) []Update {
	var out []Update
	for _, r := range rows {
		if r.IfaceIndex != ifaceIndex {
			continue
		}
		if !r.Reachable {
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

// SeedFromKernelARP is the public entry point matching the Linux
// signature. Wired to the iphlpapi syscall in the next commit.
func SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update {
	_ = ifaceName
	_ = subnet
	return nil
}
