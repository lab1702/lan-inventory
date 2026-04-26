package probe

import (
	"context"
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
	rdlen := 1 + 18*len(names)
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
