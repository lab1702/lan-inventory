// Package probe contains stateless probing functions: ping, port scan, OS
// guess by TTL, and reverse DNS lookup.
package probe

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
