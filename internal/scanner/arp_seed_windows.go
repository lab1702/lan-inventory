// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows && (amd64 || arm64)

package scanner

import (
	"net"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

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

// MIB_IPNET_ROW2 layout per Win32 (subset; only the fields we consume
// are read, but the on-disk struct size MUST match the C definition).
// Validated for amd64/arm64 (8-byte pointer alignment).
// Total size = 88 bytes on x64.
type mibIpnetRow2 struct {
	Address               sockaddrInet // 28 bytes
	InterfaceIndex        uint32       // 4 bytes
	InterfaceLuid         uint64       // 8 bytes
	PhysicalAddress       [32]byte
	PhysicalAddressLength uint32
	State                 uint32 // NL_NEIGHBOR_STATE
	Flags                 uint8
	// 3 bytes implicit padding here; Go's compiler inserts it
	// before ReachabilityTime (uint32, 4-byte alignment).
	ReachabilityTime uint32
}

// sockaddrInet matches Win32 SOCKADDR_INET — a union sized to its
// SOCKADDR_IN6 member (28 bytes). We only read the IPv4 view.
type sockaddrInet struct {
	Family uint16
	Port   uint16
	Addr4  [4]byte
	_      [20]byte // padding to SOCKADDR_INET6 size
}

const (
	nlNeighborStateUnreachable = 0
	nlNeighborStateIncomplete  = 1
	nlNeighborStateProbe       = 2
	nlNeighborStateDelay       = 3
	nlNeighborStateStale       = 4
	nlNeighborStateReachable   = 5
)

func neighborReachable(state uint32) bool {
	switch state {
	case nlNeighborStateReachable,
		nlNeighborStateStale,
		nlNeighborStateDelay,
		nlNeighborStateProbe:
		return true
	}
	return false
}

var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable2 = iphlpapi.NewProc("GetIpNetTable2")
	procFreeMibTable   = iphlpapi.NewProc("FreeMibTable")
)

// mibIpnetTable2Header matches the start of MIB_IPNET_TABLE2 — a 32-bit
// NumEntries plus 4 bytes of alignment padding so the following row
// array begins at offset 8 (MIB_IPNET_ROW2 has 8-byte alignment via its
// InterfaceLuid uint64 field).
type mibIpnetTable2Header struct {
	NumEntries uint32
	_          [4]byte
}

// SeedFromKernelARP reads the IPv4 neighbor table via iphlpapi and emits
// one Update per reachable entry on the chosen interface within subnet.
// Best-effort: returns nil on any failure.
func SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update {
	if ifaceName == "" || subnet == nil {
		return nil
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}

	const AF_INET = 2
	var tablePtr unsafe.Pointer
	ret, _, _ := procGetIpNetTable2.Call(uintptr(AF_INET), uintptr(unsafe.Pointer(&tablePtr)))
	if ret != 0 || tablePtr == nil {
		return nil
	}
	defer procFreeMibTable.Call(uintptr(tablePtr))

	header := (*mibIpnetTable2Header)(tablePtr)
	num := int(header.NumEntries)
	if num == 0 {
		return nil
	}
	rowsBase := unsafe.Add(tablePtr, unsafe.Sizeof(*header))
	rowSize := unsafe.Sizeof(mibIpnetRow2{})

	rows := make([]arpRow, 0, num)
	for i := 0; i < num; i++ {
		raw := (*mibIpnetRow2)(unsafe.Add(rowsBase, uintptr(i)*rowSize))
		if raw.Address.Family != AF_INET {
			continue
		}
		ip := net.IPv4(raw.Address.Addr4[0], raw.Address.Addr4[1], raw.Address.Addr4[2], raw.Address.Addr4[3])
		mac := make(net.HardwareAddr, 0, 6)
		if raw.PhysicalAddressLength == 6 {
			mac = append(mac, raw.PhysicalAddress[0:6]...)
		}
		rows = append(rows, arpRow{
			IfaceIndex: raw.InterfaceIndex,
			IP:         ip,
			MAC:        mac,
			Reachable:  neighborReachable(raw.State),
		})
	}
	return rowsToUpdates(rows, uint32(iface.Index), subnet, time.Now())
}
