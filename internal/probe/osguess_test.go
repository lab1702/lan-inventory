package probe

import (
	"testing"

	"github.com/lab1702/lan-inventory/internal/model"
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

func TestOSDetect(t *testing.T) {
	svcs := func(entries ...string) []model.ServiceInst {
		out := make([]model.ServiceInst, 0, len(entries))
		for _, e := range entries {
			if i := indexOf(e, '='); i > 0 {
				// "model=iPhone14,5" → ServiceInst with TXT
				out = append(out, model.ServiceInst{
					Type: "_device-info._tcp",
					TXT:  map[string]string{e[:i]: e[i+1:]},
				})
			} else {
				// "_airplay._tcp" → ServiceInst with just a type
				out = append(out, model.ServiceInst{Type: e})
			}
		}
		return out
	}
	port := func(n int) []model.Port {
		return []model.Port{{Number: n, Proto: "tcp"}}
	}

	cases := []struct {
		name          string
		vendor        string
		services      []model.ServiceInst
		openPorts     []model.Port
		nbnsResponded bool
		ttl           int
		want          string
	}{
		{"Apple TXT iPhone -> iOS", "Apple", svcs("model=iPhone14,5"), nil, false, 64, "iOS"},
		{"Apple + _apple-mobdev2 -> iOS", "Apple", svcs("_apple-mobdev2._tcp"), nil, false, 64, "iOS"},
		{"Apple TXT Mac -> macOS", "Apple", svcs("model=MacBookPro18,2"), nil, false, 64, "macOS"},
		{"Apple + _airplay -> macOS", "Apple", svcs("_airplay._tcp"), nil, false, 64, "macOS"},
		{"Apple alone -> macOS", "Apple", nil, nil, false, 64, "macOS"},
		{"NBNS no vendor -> Windows", "", nil, nil, true, 128, "Windows"},
		{"NBNS Synology -> Linux", "Synology", nil, nil, true, 64, "Linux"},
		{"Apple Boot Camp NBNS -> Windows", "Apple", nil, nil, true, 128, "Windows"},
		{"TP-Link router -> Network", "TP-Link", nil, nil, false, 255, "Network"},
		{"Espressif IoT -> Network", "Espressif", nil, nil, false, 64, "Network"},
		{"HP printer -> Network", "HP", nil, port(9100), false, 64, "Network"},
		{"RaspberryPi -> Linux", "RaspberryPi", nil, port(22), false, 64, "Linux"},
		{"_workstation -> Linux", "", svcs("_workstation._tcp"), nil, false, 64, "Linux"},
		{"TTL128+445 -> Windows", "", nil, port(445), false, 128, "Windows"},
		{"TTL64 fallback -> Linux", "", nil, nil, false, 64, "Linux"},
		{"TTL255 fallback -> Network", "", nil, nil, false, 255, "Network"},
		{"No signals -> empty", "", nil, nil, false, 0, ""},
		{"Apple Watch -> iOS", "Apple", svcs("model=Watch6,1"), nil, false, 64, "iOS"},
		{"Apple _companion-link -> macOS", "Apple", svcs("_companion-link._tcp"), nil, false, 64, "macOS"},
		{"Roku _airplay -> empty (no Apple OUI)", "Roku", svcs("_airplay._tcp"), nil, false, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := &model.Device{
				Vendor:    c.vendor,
				Services:  c.services,
				OpenPorts: c.openPorts,
				TTL:       c.ttl,
			}
			if got := OSDetect(d, c.nbnsResponded); got != c.want {
				t.Errorf("OSDetect = %q, want %q", got, c.want)
			}
		})
	}
}

// indexOf returns the index of the first b in s, or -1 if absent.
func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
