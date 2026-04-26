// Package probe contains stateless probing functions: ping, port scan, OS
// guess by TTL, and reverse DNS lookup.
package probe

import "strings"

// OSGuess returns a coarse OS family guess from an observed ICMP TTL value.
// Hosts decrement TTL by 1 per hop, so observed TTL is initial-TTL minus
// (hops - 1). On a home LAN, hops are typically 0–2.
//
//   - 32  → older Windows / some embedded
//   - 64  → Linux / macOS / *BSD / Android
//   - 128 → modern Windows
//   - 255 → routers, RTOS, network gear
//
// Returns "" for TTLs that don't plausibly correspond to any of these
// initial values (within a tolerance of 8 hops).
func OSGuess(ttl int) string {
	if ttl <= 0 {
		return ""
	}
	type bucket struct {
		initial int
		label   string
	}
	buckets := []bucket{
		{32, "Windows"},
		{64, "Linux/macOS"},
		{128, "Windows"},
		{255, "RTOS/Network"},
	}
	const tolerance = 8 // up to ~8 hops difference
	bestDelta := tolerance + 1
	best := ""
	for _, b := range buckets {
		if ttl > b.initial {
			continue
		}
		delta := b.initial - ttl
		if delta < bestDelta {
			bestDelta = delta
			best = b.label
		}
	}
	return best
}

// vendorFamily classifies a Wireshark manuf vendor short-name into a coarse
// device-class family used by OSDetect. Returns "" if no family matches.
//
// Each predicate uses case-insensitive substring matching to tolerate
// vendor short-name spelling variations (e.g., "Hewlett" vs "HP").
func vendorFamily(vendor string) string {
	v := strings.ToLower(vendor)
	switch {
	case isApple(v):
		return "Apple"
	case isRouter(v):
		return "Network"
	case isLinuxBoard(v):
		return "LinuxBoard"
	case isPrinter(v):
		return "Printer"
	case isIoT(v):
		return "IoT"
	}
	return ""
}

func isApple(v string) bool {
	return strings.Contains(v, "apple")
}

func isRouter(v string) bool {
	for _, needle := range []string{
		"tp-link", "tplink", "netgear", "ubiquiti", "cisco", "aruba",
		"juniper", "mikrotik", "d-link", "dlink", "asus", "linksys",
		"eero", "sercomm", "arris",
	} {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func isLinuxBoard(v string) bool {
	for _, needle := range []string{
		"raspberrypi", "raspberry", "synology", "qnap",
		"western digital", "buffalo",
	} {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func isPrinter(v string) bool {
	for _, needle := range []string{
		"hp", "hewlett", "canon", "brother", "epson", "xerox", "lexmark",
	} {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func isIoT(v string) bool {
	for _, needle := range []string{
		"espressif", "tuya", "shelly", "wyzelabs", "wyze", "sonos",
		"nest", "amazon", "google",
	} {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}
