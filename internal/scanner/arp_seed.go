// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lab1702/lan-inventory/internal/oui"
)

// arpFlagComplete is the ATF_COM bit (Linux): the kernel has resolved a MAC
// for the entry. Entries without this bit are INCOMPLETE/FAILED and carry a
// zero MAC.
const arpFlagComplete = 0x2

// parseProcNetARP parses /proc/net/arp content and returns one Update per row
// that:
//   - belongs to ifaceName,
//   - falls inside subnet,
//   - has the ATF_COM flag set,
//   - has a usable unicast IPv4 address and Ethernet MAC.
//
// Updates use Source "arp-seed" and the supplied discovery timestamp. The
// merger populates MAC + Vendor without claiming a fresh liveness observation:
// a complete cached entry can remain after its host has disconnected.
func parseProcNetARP(r io.Reader, ifaceName string, subnet *net.IPNet, now time.Time) []Update {
	var out []Update
	sc := bufio.NewScanner(r)
	sc.Scan() // skip header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		ipStr, flagsStr, macStr, dev := fields[0], fields[2], fields[3], fields[5]
		if dev != ifaceName {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(flagsStr, "0x"), 16, 32)
		if err != nil {
			continue
		}
		if flags&arpFlagComplete == 0 {
			continue
		}
		hw, err := net.ParseMAC(macStr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if !usableARPNeighbor(ip4, hw, subnet) {
			continue
		}
		mac := strings.ToLower(hw.String())
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

// usableARPNeighbor excludes group addresses and subnet boundaries from all
// platforms' cached neighbors. Both addresses of a /31 are usable endpoints.
func usableARPNeighbor(ip net.IP, mac net.HardwareAddr, subnet *net.IPNet) bool {
	ip4 := ip.To4()
	if subnet == nil || len(mac) != 6 || isZeroMAC(mac) || mac[0]&1 != 0 || ip4 == nil || !(ip4.IsGlobalUnicast() || ip4.IsLinkLocalUnicast()) || !subnet.Contains(ip4) {
		return false
	}
	ones, bits := subnet.Mask.Size()
	if bits != 32 {
		return false
	}
	if ones < 31 {
		network := subnet.IP.Mask(subnet.Mask).To4()
		broadcast := make(net.IP, net.IPv4len)
		for i := range broadcast {
			broadcast[i] = network[i] | ^subnet.Mask[i]
		}
		if ip4.Equal(network) || ip4.Equal(broadcast) {
			return false
		}
	}
	return true
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}
