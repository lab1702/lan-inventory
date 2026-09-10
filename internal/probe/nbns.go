// SPDX-License-Identifier: GPL-2.0-or-later

package probe

import (
	"context"
	"encoding/binary"
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
	// A status reply can contain up to 255 names, each 18 bytes, plus
	// statistics and encoded names. Preserve the whole record for validation.
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return parseNBNSResponse(buf[:n])
}

// parseNBNSResponse extracts the first non-group Workstation name from an
// NBNS Node Status Response. RFC 1002 responses have no question section;
// some implementations echo the question and compress the answer name.
func parseNBNSResponse(buf []byte) string {
	if len(buf) < 12 || binary.BigEndian.Uint16(buf[:2]) != binary.BigEndian.Uint16(nbnsQuery[:2]) {
		return ""
	}
	flags := binary.BigEndian.Uint16(buf[2:4])
	// Require a successful, untruncated standard response to our query.
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x0200 != 0 || flags&0x000f != 0 {
		return ""
	}
	questions := binary.BigEndian.Uint16(buf[4:6])
	if questions > 1 || binary.BigEndian.Uint16(buf[6:8]) != 1 ||
		binary.BigEndian.Uint16(buf[8:10]) != 0 || binary.BigEndian.Uint16(buf[10:12]) != 0 {
		return ""
	}
	off := 12
	if questions == 1 {
		var ok bool
		off, ok = skipNBNSName(buf, off)
		if !ok || off+4 > len(buf) || binary.BigEndian.Uint16(buf[off:off+2]) != 0x21 ||
			binary.BigEndian.Uint16(buf[off+2:off+4]) != 1 {
			return ""
		}
		off += 4
	}
	off, ok := skipNBNSName(buf, off)
	if !ok || off+10 > len(buf) || binary.BigEndian.Uint16(buf[off:off+2]) != 0x21 ||
		binary.BigEndian.Uint16(buf[off+2:off+4]) != 1 {
		return ""
	}
	rdlen := int(binary.BigEndian.Uint16(buf[off+8 : off+10]))
	off += 10
	if rdlen < 1 || rdlen != len(buf)-off {
		return ""
	}
	rdata := buf[off:]
	numNames := int(rdata[0])
	const recSize = 18
	// Validate every declared name and the 46-byte statistics block before
	// returning any name, including when the first record would match.
	if len(rdata) != 1+numNames*recSize+46 {
		return ""
	}
	for i := 0; i < numNames; i++ {
		off := 1 + i*recSize
		nameBytes := rdata[off : off+15]
		suffix := rdata[off+15]
		flagsHigh := rdata[off+16]
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

// skipNBNSName validates an encoded NetBIOS name and any scope labels,
// following backward compression pointers with a bounded traversal.
func skipNBNSName(buf []byte, off int) (int, bool) {
	next, expanded := -1, 0
	for steps := 0; steps < len(buf); steps++ {
		if off >= len(buf) {
			return 0, false
		}
		n := int(buf[off])
		if n&0xc0 == 0xc0 {
			if off+1 >= len(buf) {
				return 0, false
			}
			target := (n&0x3f)<<8 | int(buf[off+1])
			if target < 12 || target >= off {
				return 0, false
			}
			if next < 0 {
				next = off + 2
			}
			off = target
			continue
		}
		if n&0xc0 != 0 || off+1+n > len(buf) {
			return 0, false
		}
		if n == 0 {
			if next < 0 {
				next = off + 1
			}
			return next, expanded > 0
		}
		if expanded == 0 {
			if n != 32 {
				return 0, false
			}
			for _, c := range buf[off+1 : off+1+n] {
				if c < 'A' || c > 'P' {
					return 0, false
				}
			}
		}
		expanded += n + 1
		if expanded > 254 {
			return 0, false
		}
		off += n + 1
	}
	return 0, false
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
