// SPDX-License-Identifier: GPL-2.0-or-later

// Package probe contains stateless probing functions: ping, port scan, OS
// guess by TTL, and reverse DNS lookup.
package probe

import (
	"strings"

	"github.com/lab1702/lan-inventory/internal/model"
)

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
		"nest", "amazon", "google", "roku", "samsung",
	} {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

// OSDetect runs the multi-signal priority chain over a device's accumulated
// signals and returns one of "Windows", "macOS", "iOS", "Linux", "Network",
// or "" if no rule applies.
//
// Rule order is the resolution mechanism for conflicting signals; see the
// design doc at docs/superpowers/specs/2026-04-26-os-detection-design.md.
func OSDetect(d *model.Device, nbnsResponded bool) string {
	fam := vendorFamily(d.Vendor)
	ttlGuess := OSGuess(d.TTL)

	// Rule 1: TXT model identifies an Apple mobile/wearable device.
	if hasTXTModelPrefix(d.Services, "iphone", "ipad", "ipod", "watch") {
		return "iOS"
	}
	// Rule 2: explicit iTunes pairing service (iOS only).
	if hasService(d.Services, "_apple-mobdev2._tcp") {
		return "iOS"
	}
	// Rule 3: TXT model says Mac.
	if hasTXTModelPrefix(d.Services, "mac") {
		return "macOS"
	}
	// Rule 4: Apple OUI plus a Mac-typical mDNS service.
	if fam == "Apple" && hasService(d.Services,
		"_airplay._tcp", "_smb._tcp", "_ssh._tcp", "_device-info._tcp") {
		return "macOS"
	}
	// Rule 5: NBNS responded — strong Windows signal, but guard against
	// LinuxBoard appliances running Samba (Synology, QNAP, Pi).
	if nbnsResponded && fam != "LinuxBoard" && (ttlGuess == "Windows" || fam == "") {
		return "Windows"
	}
	// Rule 6: Apple OUI fallback when no other Apple signal is present.
	if fam == "Apple" {
		return "macOS"
	}
	// Rule 7: TTL-suggested Windows reinforced by SMB or NetBIOS port.
	if ttlGuess == "Windows" && (hasOpenPort(d.OpenPorts, 445) || hasOpenPort(d.OpenPorts, 137)) {
		return "Windows"
	}
	// Rule 8-10: Network-class vendors and appliances.
	if fam == "Network" || fam == "IoT" || fam == "Printer" {
		return "Network"
	}
	// Rule 11: Linux board/NAS vendors.
	if fam == "LinuxBoard" {
		return "Linux"
	}
	// Rule 12: Linux desktop/server hint — SSH on a TTL-64 host.
	if hasOpenPort(d.OpenPorts, 22) && ttlGuess == "Linux/macOS" {
		return "Linux"
	}
	// Rule 13: Avahi default service from a non-Apple host.
	if hasService(d.Services, "_workstation._tcp") && fam != "Apple" {
		return "Linux"
	}
	// Rule 14: open printer ports (jetdirect 9100 / IPP 631) — catches
	// printers without an OUI vendor match (e.g., when ARP hasn't filed
	// the device yet, so vendor is empty and family rules can't fire).
	if hasOpenPort(d.OpenPorts, 9100) || hasOpenPort(d.OpenPorts, 631) {
		return "Network"
	}
	// Rules 15-17: TTL-only fallbacks.
	switch ttlGuess {
	case "RTOS/Network":
		return "Network"
	case "Linux/macOS":
		return "Linux"
	case "Windows":
		return "Windows"
	}
	return ""
}

// hasService reports whether any of d.Services has Type matching one of
// the given service types.
func hasService(svcs []model.ServiceInst, types ...string) bool {
	for _, s := range svcs {
		for _, t := range types {
			if s.Type == t {
				return true
			}
		}
	}
	return false
}

// hasOpenPort reports whether any of openPorts has the given Number.
func hasOpenPort(openPorts []model.Port, port int) bool {
	for _, p := range openPorts {
		if p.Number == port {
			return true
		}
	}
	return false
}

// hasTXTModelPrefix reports whether any service's TXT["model"] begins
// (case-insensitive) with one of the given prefixes.
func hasTXTModelPrefix(svcs []model.ServiceInst, prefixes ...string) bool {
	for _, s := range svcs {
		modelStr := strings.ToLower(s.TXT["model"])
		if modelStr == "" {
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(modelStr, prefix) {
				return true
			}
		}
	}
	return false
}