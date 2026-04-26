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
	"strings"
	"sync"
)

//go:embed manuf.txt
var manufRaw string

var (
	once  sync.Once
	table map[string]string
)

func loadTable() {
	table = make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(manufRaw))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			continue
		}
		prefix := strings.ToUpper(strings.TrimSpace(parts[0]))
		if strings.Contains(prefix, "/") {
			continue
		}
		short := strings.TrimSpace(parts[1])
		if prefix == "" || short == "" {
			continue
		}
		table[prefix] = short
	}
}

// Lookup returns the vendor short-name for the given MAC, or "" if unknown.
// Accepts uppercase or lowercase, with colon separators.
func Lookup(mac string) string {
	once.Do(loadTable)
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToUpper(mac[:8])
	if !strings.Contains(prefix, ":") {
		return ""
	}
	return table[prefix]
}
