// SPDX-License-Identifier: GPL-2.0-or-later

package oui

import (
	"strings"
	"testing"
)

// Synthetic manuf data exercising /24, /28, and /36 allocations, including a
// /24 parent that is subdivided into a longer /28 and /36 owned by others.
const synthManuf = `# comment line
00:11:22	ParentCo	Parent Company, Inc.
00:11:22:30:00:00/28	SubM	Sub MA-M Vendor
00:11:22:31:40:00/36	SubS	Sub MA-S Vendor
AA:BB:CC	OnlyShort
`

func TestBuildTablesLongestPrefixMatch(t *testing.T) {
	short, long, nibbles := buildTables(strings.NewReader(synthManuf))

	// Swap in the synthetic tables for the lookup helpers.
	shortByPrefix, longByPrefix, maskNibbles = short, long, nibbles

	cases := []struct {
		mac       string
		wantShort string
		wantLong  string
	}{
		// Falls under the /24 parent only.
		{"00:11:22:00:00:01", "ParentCo", "Parent Company, Inc."},
		// /28 sub-block wins over the /24 parent (00:11:22:3x).
		{"00:11:22:30:ab:cd", "SubM", "Sub MA-M Vendor"},
		// /36 sub-block wins over both the /28 and /24 (00:11:22:31:4x).
		{"00:11:22:31:40:99", "SubS", "Sub MA-S Vendor"},
		// 00:11:22:31:5x is inside the /28's 3x range but outside the /36, so
		// it should match the /28, not the /36.
		{"00:11:22:31:50:00", "SubM", "Sub MA-M Vendor"},
		// Short-name-only entry: Lookup finds it, LookupLong returns "".
		{"aa:bb:cc:de:ad:01", "OnlyShort", ""},
		// Unknown OUI.
		{"99:99:99:00:00:00", "", ""},
		// Separator-insensitive (dashes, no separators).
		{"00-11-22-30-00-00", "SubM", "Sub MA-M Vendor"},
		{"001122000001", "ParentCo", "Parent Company, Inc."},
	}
	for _, c := range cases {
		if got := lookupIn(shortByPrefix, c.mac); got != c.wantShort {
			t.Errorf("short lookup(%q) = %q, want %q", c.mac, got, c.wantShort)
		}
		if got := lookupIn(longByPrefix, c.mac); got != c.wantLong {
			t.Errorf("long lookup(%q) = %q, want %q", c.mac, got, c.wantLong)
		}
	}
}

func TestNormalizePrefix(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"00:11:22", "001122", true},
		{"00:11:22:30:00:00/28", "0011223", true},
		{"00:11:22:31:40:00/36", "001122314", true},
		{"00:11:22/24", "001122", true},
		{"00:11:22:33:00:00/30", "", false}, // not nibble-aligned
		{"00:11:22:33:00:00/0", "", false},  // zero bits
		{"garbage", "", false},
		{"00:11:22:33:00:00/notanumber", "", false},
	}
	for _, c := range cases {
		got, ok := normalizePrefix(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("normalizePrefix(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
