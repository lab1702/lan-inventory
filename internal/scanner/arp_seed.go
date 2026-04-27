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

const zeroMAC = "00:00:00:00:00:00"

// parseProcNetARP parses /proc/net/arp content and returns one Update per row
// that:
//   - belongs to ifaceName,
//   - falls inside subnet,
//   - has the ATF_COM flag set,
//   - has a non-zero, parseable MAC.
//
// Updates use Source "arp-seed" and the supplied now timestamp; the merger
// treats them like any other ARP sighting, populating MAC + Vendor for hosts
// the kernel already knows but for which no ARP traffic has crossed the wire
// during the scan window.
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
		if macStr == zeroMAC {
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
		if ip4 == nil || !subnet.Contains(ip4) {
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
