// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !linux && !windows && !darwin

package scanner

import "net"

// SeedFromKernelARP is a no-op on *BSD platforms (FreeBSD, OpenBSD,
// NetBSD). Linux uses /proc/net/arp; Windows and macOS use
// platform-specific implementations. *BSD startup hard-fails earlier
// in route detection anyway, so this no-op is dead code in practice
// but kept for build-tag symmetry.
func SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update {
	return nil
}
