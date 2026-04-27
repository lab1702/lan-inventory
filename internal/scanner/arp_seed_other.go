// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux

package scanner

import "net"

// SeedFromKernelARP is a no-op on non-Linux platforms. /proc/net/arp is
// Linux-specific; macOS/BSD use sysctl(NET_RT_FLAGS) and Windows uses
// GetIpNetTable, neither of which is wired up. ARPWorker still functions
// (libpcap is cross-platform), so non-Linux users only lose the startup
// shortcut, not correctness.
func SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update {
	return nil
}
