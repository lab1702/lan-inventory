// SPDX-License-Identifier: GPL-2.0-or-later

package probe

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// makeNBNSResponse builds a minimal NBNS Node Status Response containing the
// given names. Each name is space-padded to 15 chars + 1 byte suffix + 2
// bytes flags. suffixes[i] is the suffix type byte (0x00 = Workstation).
// groupFlags[i] true sets the group bit in the flags field.
func makeNBNSResponse(names []string, suffixes []byte, groupFlags []bool) []byte {
	// 12-byte header: flags 0x8500 = response, recursion not desired
	hdr := []byte{
		0x12, 0x34, 0x85, 0x00,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	}
	// 38-byte question section: length 32 + encoded "CK" + 30x"A" + NUL + type + class
	q := []byte{0x20, 'C', 'K'}
	for i := 0; i < 30; i++ {
		q = append(q, 'A')
	}
	q = append(q, 0x00, 0x00, 0x21, 0x00, 0x01)

	// 12-byte answer header: name pointer + type + class + TTL + RDLENGTH
	rdlen := 1 + 18*len(names) + 46
	ans := []byte{
		0xC0, 0x0C,
		0x00, 0x21,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		byte(rdlen >> 8), byte(rdlen & 0xff),
	}

	rdata := []byte{byte(len(names))}
	for i, name := range names {
		nameBytes := make([]byte, 16)
		// pad to 15 chars with spaces
		for j := 0; j < 15; j++ {
			if j < len(name) {
				nameBytes[j] = name[j]
			} else {
				nameBytes[j] = ' '
			}
		}
		nameBytes[15] = suffixes[i]
		var flags [2]byte
		if groupFlags[i] {
			flags[0] = 0x80
		}
		rdata = append(rdata, nameBytes...)
		rdata = append(rdata, flags[:]...)
	}
	rdata = append(rdata, make([]byte, 46)...)

	out := append([]byte{}, hdr...)
	out = append(out, q...)
	out = append(out, ans...)
	out = append(out, rdata...)
	return out
}

func TestParseNBNSResponseValid(t *testing.T) {
	resp := makeNBNSResponse(
		[]string{"DESKTOP-A"},
		[]byte{0x00},
		[]bool{false},
	)
	got := parseNBNSResponse(resp)
	if got != "DESKTOP-A" {
		t.Errorf("got %q, want %q", got, "DESKTOP-A")
	}
}

func TestParseNBNSResponseGroupSkipped(t *testing.T) {
	// A single Workstation-suffix name but with the group bit set should be skipped.
	resp := makeNBNSResponse(
		[]string{"WORKGROUP"},
		[]byte{0x00},
		[]bool{true},
	)
	got := parseNBNSResponse(resp)
	if got != "" {
		t.Errorf("group-only response should yield empty, got %q", got)
	}
}

func TestParseNBNSResponseTooShort(t *testing.T) {
	got := parseNBNSResponse([]byte{0x12, 0x34, 0x85, 0x00})
	if got != "" {
		t.Errorf("too-short buffer should yield empty, got %q", got)
	}
}

func TestParseNBNSResponseEmptyList(t *testing.T) {
	resp := makeNBNSResponse(nil, nil, nil)
	got := parseNBNSResponse(resp)
	if got != "" {
		t.Errorf("empty-list response should yield empty, got %q", got)
	}
}

func TestParseNBNSResponseNoQuestion(t *testing.T) {
	resp := makeNBNSResponse([]string{"STANDARD-HOST"}, []byte{0}, []bool{false})
	// RFC 1002 section 4.2.18 has QDCOUNT=0 and an uncompressed RR_NAME.
	standard := append([]byte{}, resp[:12]...)
	standard[5] = 0
	standard = append(standard, nbnsQuery[12:46]...)
	standard = append(standard, resp[52:]...)
	if got := parseNBNSResponse(standard); got != "STANDARD-HOST" {
		t.Fatalf("standard response = %q, want STANDARD-HOST", got)
	}
	for n := 0; n < len(standard); n++ {
		if got := parseNBNSResponse(standard[:n]); got != "" {
			t.Fatalf("truncated response of %d bytes = %q, want empty", n, got)
		}
	}
}

func TestParseNBNSResponseFullNameTable(t *testing.T) {
	names, suffixes, groups := make([]string, 255), make([]byte, 255), make([]bool, 255)
	for i := range names {
		names[i], groups[i] = "GROUP", true
	}
	names[254], groups[254] = "LAST-HOST", false
	if got := parseNBNSResponse(makeNBNSResponse(names, suffixes, groups)); got != "LAST-HOST" {
		t.Fatalf("full name table = %q, want LAST-HOST", got)
	}
}

func TestParseNBNSResponseMalformed(t *testing.T) {
	tests := []struct {
		name string
		edit func([]byte) []byte
	}{
		{"wrong transaction", func(b []byte) []byte { b[1]++; return b }},
		{"query packet", func(b []byte) []byte { b[2] &^= 0x80; return b }},
		{"wrong opcode", func(b []byte) []byte { b[2] |= 0x08; return b }},
		{"truncated flag", func(b []byte) []byte { b[2] |= 0x02; return b }},
		{"error status", func(b []byte) []byte { b[3] |= 1; return b }},
		{"extra question", func(b []byte) []byte { b[5] = 2; return b }},
		{"no answer", func(b []byte) []byte { b[7] = 0; return b }},
		{"extra answer", func(b []byte) []byte { b[7] = 2; return b }},
		{"authority record", func(b []byte) []byte { b[9] = 1; return b }},
		{"additional record", func(b []byte) []byte { b[11] = 1; return b }},
		{"bad question type", func(b []byte) []byte { b[47] = 0x20; return b }},
		{"bad question class", func(b []byte) []byte { b[49] = 2; return b }},
		{"bad answer type", func(b []byte) []byte { b[53] = 0x20; return b }},
		{"bad answer class", func(b []byte) []byte { b[55] = 2; return b }},
		{"empty rdata", func(b []byte) []byte { b[60], b[61] = 0, 0; return b }},
		{"short rdata length", func(b []byte) []byte { b[61]--; return b }},
		{"long rdata length", func(b []byte) []byte { b[61]++; return b }},
		{"missing declared name", func(b []byte) []byte { b[62]++; return b }},
		{"truncated last record", func(b []byte) []byte {
			b = b[:len(b)-47]
			binary.BigEndian.PutUint16(b[60:62], uint16(len(b)-62))
			return b
		}},
		{"missing statistics", func(b []byte) []byte {
			b = b[:len(b)-1]
			binary.BigEndian.PutUint16(b[60:62], uint16(len(b)-62))
			return b
		}},
		{"bad encoded label", func(b []byte) []byte { b[13] = 'Z'; return b }},
		{"invalid label length", func(b []byte) []byte { b[12] = 0x80; return b }},
		{"pointer to header", func(b []byte) []byte { b[51] = 0; return b }},
		{"self pointer", func(b []byte) []byte { b[51] = 50; return b }},
		{"forward pointer", func(b []byte) []byte { b[51] = 80; return b }},
		{"pointer cycle", func(b []byte) []byte { b[45], b[46] = 0xc0, 0x0c; return b }},
		{"truncated pointer", func(b []byte) []byte { return b[:51] }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeNBNSResponse([]string{"FIRST", "SECOND"}, []byte{0, 0}, []bool{false, false})
			if got := parseNBNSResponse(tt.edit(resp)); got != "" {
				t.Fatalf("malformed response returned %q", got)
			}
		})
	}
}

func TestParseNBNSResponseSecondNameWins(t *testing.T) {
	// First name is a group, second is the unique Workstation. We should
	// skip the first and return the second.
	resp := makeNBNSResponse(
		[]string{"WORKGROUP", "MYHOST"},
		[]byte{0x00, 0x00},
		[]bool{true, false},
	)
	got := parseNBNSResponse(resp)
	if got != "MYHOST" {
		t.Errorf("got %q, want %q", got, "MYHOST")
	}
}

func TestParseNBNSResponseTrimsSpaces(t *testing.T) {
	resp := makeNBNSResponse(
		[]string{"H"},
		[]byte{0x00},
		[]bool{false},
	)
	got := parseNBNSResponse(resp)
	if got != "H" {
		t.Errorf("got %q, want %q (spaces should be trimmed)", got, "H")
	}
}

func TestParseNBNSResponseSkipsNonWorkstationSuffix(t *testing.T) {
	// Suffix 0x20 = File Server. The parser should skip it and return "".
	resp := makeNBNSResponse(
		[]string{"FILESERVER"},
		[]byte{0x20},
		[]bool{false},
	)
	got := parseNBNSResponse(resp)
	if got != "" {
		t.Errorf("non-Workstation suffix should yield empty, got %q", got)
	}
}

func TestNBNSQueryFormat(t *testing.T) {
	if len(nbnsQuery) != 50 {
		t.Fatalf("nbnsQuery length: got %d, want 50", len(nbnsQuery))
	}
	// Header: QDCOUNT must be 1.
	if nbnsQuery[4] != 0x00 || nbnsQuery[5] != 0x01 {
		t.Errorf("QDCOUNT: got %#x %#x, want 0x00 0x01", nbnsQuery[4], nbnsQuery[5])
	}
	// Question type at offset 12 + 1 + 32 + 1 = 46: should be 0x00 0x21 (NBSTAT).
	if nbnsQuery[46] != 0x00 || nbnsQuery[47] != 0x21 {
		t.Errorf("QTYPE: got %#x %#x, want 0x00 0x21 (NBSTAT)", nbnsQuery[46], nbnsQuery[47])
	}
	// Question class at offset 48: should be 0x00 0x01 (IN).
	if nbnsQuery[48] != 0x00 || nbnsQuery[49] != 0x01 {
		t.Errorf("QCLASS: got %#x %#x, want 0x00 0x01 (IN)", nbnsQuery[48], nbnsQuery[49])
	}
}

func TestNBNSLocalhostSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	// Localhost rarely runs nmbd, so we typically expect "". If a developer's
	// box does run Samba, the response is non-empty. Either is fine — we
	// only verify the function doesn't panic or hang past the timeout.
	_ = NBNS(ctx, "127.0.0.1")
}

func TestSanitizeNetBIOSName(t *testing.T) {
	build := func(prefix string, padByte byte) []byte {
		out := make([]byte, 15)
		for i := range out {
			out[i] = padByte
		}
		copy(out, prefix)
		return out
	}
	cases := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "all-ASCII space-padded",
			input: build("HOSTNAME", ' '),
			want:  "HOSTNAME",
		},
		{
			name:  "non-printable byte terminates name",
			input: append([]byte("OUP"), 0xC2, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K'),
			want:  "OUP",
		},
		{
			name:  "NUL-padded after name",
			input: append([]byte("MYHOST"), 0, 0, 0, 0, 0, 0, 0, 0, 0),
			want:  "MYHOST",
		},
		{
			name:  "all spaces",
			input: build("", ' '),
			want:  "",
		},
		{
			name:  "starts with non-printable",
			input: append([]byte{0xFF}, []byte("HOSTNAME      ")...),
			want:  "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeNetBIOSName(c.input); got != c.want {
				t.Errorf("sanitizeNetBIOSName(%v) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}
