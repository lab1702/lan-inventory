package probe

import (
	"testing"
)

func TestOSGuess(t *testing.T) {
	cases := []struct {
		ttl  int
		want string
	}{
		{0, ""},
		{32, "Windows"},          // older Windows / some embedded
		{64, "Linux/macOS"},      // typical Unix
		{128, "Windows"},          // modern Windows
		{255, "RTOS/Network"},    // routers, embedded RTOS
		{63, "Linux/macOS"},      // 1 hop away from 64
		{60, "Linux/macOS"},
		{127, "Windows"},
		{254, "RTOS/Network"},
		{248, "RTOS/Network"},    // 7 hops below 255 — within tolerance
		{200, ""},                 // 55 hops below 255 — outside tolerance
		{1, ""},                   // nonsense
	}
	for _, c := range cases {
		got := OSGuess(c.ttl)
		if got != c.want {
			t.Errorf("OSGuess(%d) = %q, want %q", c.ttl, got, c.want)
		}
	}
}

func TestVendorFamily(t *testing.T) {
	cases := []struct {
		vendor string
		want   string
	}{
		{"Apple, Inc.", "Apple"},
		{"Apple", "Apple"},
		{"Raspberry Pi Foundation", "LinuxBoard"},
		{"RaspberryPiF", "LinuxBoard"},
		{"Synology Incorporated", "LinuxBoard"},
		{"TP-LINK TECHNOLOGIES CO.,LTD.", "Network"},
		{"Netgear", "Network"},
		{"Ubiquiti Networks Inc.", "Network"},
		{"Cisco Systems, Inc", "Network"},
		{"Hewlett Packard", "Printer"},
		{"HP", "Printer"},
		{"Canon Inc.", "Printer"},
		{"Espressif Inc.", "IoT"},
		{"Sonos, Inc.", "IoT"},
		{"WyzeLabs", "IoT"},
		{"", ""},
		{"SomeUnknownVendor", ""},
	}
	for _, c := range cases {
		if got := vendorFamily(c.vendor); got != c.want {
			t.Errorf("vendorFamily(%q) = %q, want %q", c.vendor, got, c.want)
		}
	}
}
