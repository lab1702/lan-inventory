// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

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

	handle, _, _ := procIcmpCreateFile.Call()
	if handle == 0 || handle == invalidHandle {
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
	replyBufLen := int(unsafe.Sizeof(icmpEchoReply{})) + len(requestData) + 8
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

// ipv4ToIPAddr packs an IPv4 net.IP into the uint32 value Win32 expects
// for an IPAddr (network byte order, little-endian-loaded).
func ipv4ToIPAddr(ip4 net.IP) uint32 {
	return uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
}

// icmpEchoReply mirrors ICMP_ECHO_REPLY from <ipexport.h>. The pointer
// fields (Data, OptionsData) are sized for x64; on 32-bit Windows the
// layout differs and this struct will need adjustment.
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
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)
