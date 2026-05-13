// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux && !windows

package scanner

import "net"

// SeedFromKernelARP is a no-op on macOS/BSD platforms. /proc/net/arp is
// Linux-specific; macOS/BSD use sysctl(NET_RT_FLAGS) which is not wired
// up. ARPWorker still functions (libpcap is cross-platform), so users
// only lose the startup shortcut, not correctness.
func SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update {
	return nil
}
