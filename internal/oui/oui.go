// SPDX-License-Identifier: GPL-2.0-or-later

// Package oui resolves a MAC address to a vendor short-name using an
// embedded copy of Wireshark's manuf database.
//
// The bundled manuf.txt and its license (MANUF-LICENSE) are fetched from
// https://www.wireshark.org/download/automated/data/manuf and
// https://gitlab.com/wireshark/wireshark/-/raw/master/COPYING respectively,
// via `make manuf-refresh`.
package oui

import (
	"bufio"
	_ "embed"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed manuf.txt
var manufRaw string

var (
	once sync.Once
	// Prefix maps keyed by an uppercase hex string with no separators. The key
	// length in nibbles encodes the mask: 6 = /24 (MA-L), 7 = /28 (MA-M),
	// 9 = /36 (MA-S). Storing the mask in the key length lets a single map hold
	// allocations of every width.
	shortByPrefix map[string]string
	longByPrefix  map[string]string
	// Distinct prefix lengths (in nibbles) present in the data, longest first,
	// so lookups can do longest-prefix matching.
	maskNibbles []int
)

func loadTable() {
	shortByPrefix, longByPrefix, maskNibbles = buildTables(strings.NewReader(manufRaw))
}

// buildTables parses a Wireshark manuf stream into prefix→name maps plus the
// sorted set of prefix lengths. Split out from loadTable so it can be tested
// with synthetic input.
func buildTables(r io.Reader) (short, long map[string]string, nibbles []int) {
	short = make(map[string]string)
	long = make(map[string]string)
	nibbleSet := map[int]struct{}{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			continue
		}
		key, ok := normalizePrefix(parts[0])
		if !ok {
			continue
		}
		shortName := strings.TrimSpace(parts[1])
		if shortName == "" {
			continue
		}
		short[key] = shortName
		nibbleSet[len(key)] = struct{}{}
		if len(parts) >= 3 {
			if longName := strings.TrimSpace(parts[2]); longName != "" {
				long[key] = longName
			}
		}
	}

	for n := range nibbleSet {
		nibbles = append(nibbles, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nibbles)))
	return short, long, nibbles
}

// normalizePrefix converts a manuf first-field ("AA:BB:CC" or
// "AA:BB:CC:D0:00:00/28") into the uppercase hex prefix covering the masked
// bits, with separators stripped. A bare prefix is treated as /24. Only
// nibble-aligned masks (multiples of 4 bits — which is all Wireshark emits:
// /24, /28, /36) are supported; anything else is skipped.
func normalizePrefix(field string) (string, bool) {
	field = strings.TrimSpace(field)
	bits := 24
	if i := strings.IndexByte(field, '/'); i >= 0 {
		b, err := strconv.Atoi(strings.TrimSpace(field[i+1:]))
		if err != nil {
			return "", false
		}
		bits = b
		field = field[:i]
	}
	if bits <= 0 || bits > 48 || bits%4 != 0 {
		return "", false
	}
	hex, ok := normalizeHex(field)
	if !ok {
		return "", false
	}
	nibbles := bits / 4
	if len(hex) < nibbles {
		return "", false
	}
	return hex[:nibbles], true
}

// normalizeHex uppercases s and drops the ':', '-', and '.' separators
// commonly used in MAC notation, returning only the hex digits. A non-hex,
// non-separator byte aborts the conversion (ok=false).
func normalizeHex(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'F':
			b.WriteByte(c)
		case c >= 'a' && c <= 'f':
			b.WriteByte(c - ('a' - 'A'))
		case c == ':' || c == '-' || c == '.':
			// separator — skip
		default:
			return "", false
		}
	}
	return b.String(), true
}

func lookupIn(m map[string]string, mac string) string {
	hex, ok := normalizeHex(mac)
	if !ok || len(hex) < 6 { // need at least the 24-bit OUI
		return ""
	}
	for _, n := range maskNibbles {
		if n > len(hex) {
			continue
		}
		if v, ok := m[hex[:n]]; ok {
			return v
		}
	}
	return ""
}

// Lookup returns the vendor short-name for the given MAC, or "" if unknown.
// Accepts upper- or lowercase, with ':' / '-' / '.' separators or none.
// Matches the longest registered prefix (/36, then /28, then /24).
func Lookup(mac string) string {
	once.Do(loadTable)
	return lookupIn(shortByPrefix, mac)
}

// LookupLong returns the vendor long-name (manuf.txt 3rd column) for the given
// MAC, or "" if unknown. Some entries have only a short name; in that case
// LookupLong returns "".
func LookupLong(mac string) string {
	once.Do(loadTable)
	return lookupIn(longByPrefix, mac)
}
