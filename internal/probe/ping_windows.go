// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows && (amd64 || arm64)

package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Ping sends a single ICMP echo to the given IP using the Win32
// IcmpSendEcho API (iphlpapi.dll). This avoids the raw-socket / unprivileged-
// UDP-ICMP dance that does not work on Windows and runs without
// Administrator privilege.
func Ping(ctx context.Context, ip string) (PingResult, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return PingResult{}, fmt.Errorf("ping: invalid IP %q", ip)
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return PingResult{}, fmt.Errorf("ping: not IPv4 %q", ip)
	}
	dest := ipv4ToIPAddr(ip4)

	if err := ctx.Err(); err != nil {
		return PingResult{}, fmt.Errorf("ping: %w", err)
	}

	handle, _, _ := procIcmpCreateFile.Call()
	if handle == invalidHandle {
		return PingResult{}, errors.New("ping: IcmpCreateFile failed")
	}
	defer procIcmpCloseHandle.Call(handle)

	timeoutMs := uint32(1000)
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl).Milliseconds(); rem > 0 && rem < int64(timeoutMs) {
			timeoutMs = uint32(rem)
		}
	}

	requestData := []byte("lan-inventory")
	replyBufLen := int(unsafe.Sizeof(icmpEchoReply{})) + len(requestData) + icmpReplyGuardBytes
	replyBuf := make([]byte, replyBufLen)

	ret, _, _ := procIcmpSendEcho.Call(
		handle,
		uintptr(dest),
		uintptr(unsafe.Pointer(&requestData[0])),
		uintptr(len(requestData)),
		0,
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(replyBufLen),
		uintptr(timeoutMs),
	)
	if ret == 0 {
		return PingResult{Alive: false}, nil
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status != ipStatusSuccess {
		return PingResult{Alive: false}, nil
	}
	return PingResult{
		Alive: true,
		RTT:   time.Duration(reply.RoundTripTime) * time.Millisecond,
		TTL:   int(reply.OptionsTtl),
	}, nil
}

// ipv4ToIPAddr packs the four octets into a uint32 so their in-memory
// layout on a little-endian host is octets[0]..octets[3] — the bytewise
// representation Win32's IPAddr uses.
func ipv4ToIPAddr(ip4 net.IP) uint32 {
	return uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
}

// icmpEchoReply mirrors ICMP_ECHO_REPLY from <ipexport.h>.
// Layout validated for amd64 and arm64 (8-byte pointer fields).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	OptionsTtl    uint8
	OptionsTos    uint8
	OptionsFlags  uint8
	OptionsSize   uint8
	OptionsData   uintptr
}

const (
	ipStatusSuccess uint32 = 0
	invalidHandle          = ^uintptr(0)
	// icmpReplyGuardBytes is the +8 byte margin MSDN's IcmpSendEcho reference
	// requires beyond sizeof(ICMP_ECHO_REPLY) + RequestSize, to leave room
	// for an embedded ICMP error message if the ping fails.
	icmpReplyGuardBytes = 8
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)
