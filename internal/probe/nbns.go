// SPDX-License-Identifier: GPL-2.0-or-later

package probe

import (
	"context"
	"net"
	"strings"
	"time"
)

// nbnsQuery is the 50-byte NBNS Node Status Request datagram.
//
// 12-byte DNS-style header:
//   - Transaction ID 0x1234
//   - Flags 0x0000 (standard query, no broadcast)
//   - QDCOUNT 1, ANCOUNT 0, NSCOUNT 0, ARCOUNT 0
//
// Encoded NetBIOS wildcard name: length 0x20, then "CK" (which is the
// nibble-encoding of '*' = 0x2A: 'A' + 0x2 = 'C', 'A' + 0xA = 'K') followed
// by 30 'A' characters (the encoding of 15 NUL bytes), terminated with NUL.
//
// Question type 0x0021 (NBSTAT), class 0x0001 (IN).
var nbnsQuery = []byte{
	// header
	0x12, 0x34, // transaction ID
	0x00, 0x00, // flags
	0x00, 0x01, // QDCOUNT
	0x00, 0x00, // ANCOUNT
	0x00, 0x00, // NSCOUNT
	0x00, 0x00, // ARCOUNT
	// encoded name: length + 2-char '*' + 30-char NULs + terminator
	0x20,
	'C', 'K',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
	0x00,
	// QTYPE NBSTAT
	0x00, 0x21,
	// QCLASS IN
	0x00, 0x01,
}

// NBNS sends an NBNS Node Status Request to ip:137 and returns the device's
// Workstation/Redirector name. Returns "" on no response, timeout, or any
// parse error. Bounded by a 500 ms read deadline.
//
// Devices that don't speak NBNS (most Linux/macOS, IoT) simply ignore the
// query and we hit the read deadline. One stray UDP packet per scan cycle
// per host — negligible noise.
func NBNS(ctx context.Context, ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	addr := &net.UDPAddr{IP: parsed, Port: 137}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	deadline := time.Now().Add(500 * time.Millisecond)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return ""
	}

	if _, err := conn.Write(nbnsQuery); err != nil {
		return ""
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return parseNBNSResponse(buf[:n])
}

// parseNBNSResponse extracts the first non-group Workstation name from an
// NBNS Node Status Response. Layout:
//
//	[0..12)   header
//	[12..50)  question section (echoes our 38-byte question)
//	[50..62)  answer section header (name ptr + type + class + TTL + RDLENGTH)
//	[62]      NUM_NAMES
//	[63..)    NAME_RECORDS, each 18 bytes:
//	             15 bytes name (space-padded)
//	              1 byte suffix type (0x00 = Workstation/Redirector)
//	              2 bytes flags (top bit of first byte = group)
//
// A valid response is at least 12 + 38 + 12 + 1 + 18 = 81 bytes.
func parseNBNSResponse(buf []byte) string {
	const minLen = 81
	if len(buf) < minLen {
		return ""
	}
	numNames := int(buf[62])
	if numNames == 0 {
		return ""
	}
	const recBase = 63
	const recSize = 18
	for i := 0; i < numNames; i++ {
		off := recBase + i*recSize
		if off+recSize > len(buf) {
			break
		}
		nameBytes := buf[off : off+15]
		suffix := buf[off+15]
		flagsHigh := buf[off+16]
		// Suffix 0x00 is Workstation/Redirector — the actual machine name.
		if suffix != 0x00 {
			continue
		}
		// Top bit of the flags' first byte = Group flag. We want unique names.
		if flagsHigh&0x80 != 0 {
			continue
		}
		name := sanitizeNetBIOSName(nameBytes)
		if name == "" {
			continue
		}
		return name
	}
	return ""
}

// sanitizeNetBIOSName converts the 15-byte name field from an NBNS name
// record into a printable string. Per RFC 1001 §14, NetBIOS names are
// case-insensitive ASCII strings padded with spaces; in practice some
// devices fill the field with non-printable bytes (extended-ASCII or
// NUL-terminated then garbage), which display as replacement characters
// in a UTF-8 terminal. We treat the first non-printable-ASCII byte as
// end-of-name and trim trailing spaces.
func sanitizeNetBIOSName(nameBytes []byte) string {
	out := make([]byte, 0, len(nameBytes))
	for _, c := range nameBytes {
		if c < 0x20 || c > 0x7E {
			break
		}
		out = append(out, c)
	}
	return strings.TrimRight(string(out), " ")
}