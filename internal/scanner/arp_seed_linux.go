// SPDX-License-Identifier: GPL-2.0-or-later

//go:build linux

package scanner

import (
	"net"
	"os"
	"time"
)

// SeedFromKernelARP reads the kernel's ARP cache from /proc/net/arp and
// returns one Update per neighbor that the kernel has already resolved for
// ifaceName within subnet. Returns nil on any read error — seeding is
// best-effort and not worth failing startup over.
//
// The passive ARPWorker only sees ARP packets that traverse the wire during
// the scan window. When the kernel cache is already populated, ICMP/TCP
// probes reuse those entries without emitting fresh ARP requests, leaving
// affected hosts visible to the active prober but MAC-less in the device
// map. Seeding closes that gap.
func SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update {
	if ifaceName == "" || subnet == nil {
		return nil
	}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseProcNetARP(f, ifaceName, subnet, time.Now())
}
