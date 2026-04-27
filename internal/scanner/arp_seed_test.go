// SPDX-License-Identifier: GPL-2.0-or-later

package scanner

import (
	"net"
	"strings"
	"testing"
	"time"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad CIDR %q: %v", s, err)
	}
	return n
}

func TestParseProcNetARP_BasicHappyPath(t *testing.T) {
	in := `IP address       HW type     Flags       HW address            Mask     Device
192.168.0.139    0x1         0x2         08:3a:8d:8e:3e:f0     *        enp195s0
192.168.0.246    0x1         0x2         02:81:45:19:9e:c6     *        enp195s0
`
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	got := parseProcNetARP(strings.NewReader(in), "enp195s0", mustCIDR(t, "192.168.0.0/24"), now)
	if len(got) != 2 {
		t.Fatalf("want 2 updates, got %d (%v)", len(got), got)
	}
	for _, u := range got {
		if u.Source != "arp-seed" {
			t.Errorf("Source = %q, want arp-seed", u.Source)
		}
		if !u.Time.Equal(now) {
			t.Errorf("Time = %v, want %v", u.Time, now)
		}
		if u.MAC == "" || u.IP == nil {
			t.Errorf("missing MAC or IP: %+v", u)
		}
		if u.MAC != strings.ToLower(u.MAC) {
			t.Errorf("MAC %q not lowercase", u.MAC)
		}
	}
	if got[0].MAC != "08:3a:8d:8e:3e:f0" || got[0].IP.String() != "192.168.0.139" {
		t.Errorf("row 0 mismatch: %+v", got[0])
	}
	if got[1].MAC != "02:81:45:19:9e:c6" || got[1].IP.String() != "192.168.0.246" {
		t.Errorf("row 1 mismatch: %+v", got[1])
	}
}

func TestParseProcNetARP_FiltersWrongInterface(t *testing.T) {
	in := `IP address       HW type     Flags       HW address            Mask     Device
192.168.0.139    0x1         0x2         08:3a:8d:8e:3e:f0     *        enp195s0
10.0.0.5         0x1         0x2         aa:bb:cc:dd:ee:ff     *        docker0
`
	got := parseProcNetARP(strings.NewReader(in), "enp195s0", mustCIDR(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 {
		t.Fatalf("want 1 update (enp195s0 only), got %d", len(got))
	}
	if got[0].IP.String() != "192.168.0.139" {
		t.Errorf("wrong row kept: %+v", got[0])
	}
}

func TestParseProcNetARP_FiltersOutsideSubnet(t *testing.T) {
	// Same interface, different subnet — possible with secondary addrs.
	in := `IP address       HW type     Flags       HW address            Mask     Device
192.168.0.139    0x1         0x2         08:3a:8d:8e:3e:f0     *        enp195s0
192.168.5.10     0x1         0x2         aa:bb:cc:dd:ee:ff     *        enp195s0
`
	got := parseProcNetARP(strings.NewReader(in), "enp195s0", mustCIDR(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || got[0].IP.String() != "192.168.0.139" {
		t.Fatalf("subnet filter failed: %+v", got)
	}
}

func TestParseProcNetARP_FiltersIncompleteFlag(t *testing.T) {
	// Flags 0x0 = incomplete (no MAC resolved yet); 0x2 = ATF_COM (complete).
	in := `IP address       HW type     Flags       HW address            Mask     Device
192.168.0.50     0x1         0x0         00:00:00:00:00:00     *        enp195s0
192.168.0.51     0x1         0x2         08:3a:8d:8e:3e:f0     *        enp195s0
`
	got := parseProcNetARP(strings.NewReader(in), "enp195s0", mustCIDR(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || got[0].IP.String() != "192.168.0.51" {
		t.Fatalf("flag filter failed: %+v", got)
	}
}

func TestParseProcNetARP_FiltersZeroMAC(t *testing.T) {
	// Even with ATF_COM bit set, a 00:00:00:00:00:00 MAC is meaningless.
	in := `IP address       HW type     Flags       HW address            Mask     Device
192.168.0.50     0x1         0x2         00:00:00:00:00:00     *        enp195s0
192.168.0.51     0x1         0x2         08:3a:8d:8e:3e:f0     *        enp195s0
`
	got := parseProcNetARP(strings.NewReader(in), "enp195s0", mustCIDR(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || got[0].IP.String() != "192.168.0.51" {
		t.Fatalf("zero-MAC filter failed: %+v", got)
	}
}

func TestParseProcNetARP_SkipsMalformedRows(t *testing.T) {
	in := `IP address       HW type     Flags       HW address            Mask     Device
not-an-ip        0x1         0x2         08:3a:8d:8e:3e:f0     *        enp195s0
192.168.0.51     0x1         bogus       08:3a:8d:8e:3e:f0     *        enp195s0
192.168.0.52     0x1         0x2         not-a-mac             *        enp195s0
short row
192.168.0.53     0x1         0x2         08:3a:8d:8e:3e:f1     *        enp195s0
`
	got := parseProcNetARP(strings.NewReader(in), "enp195s0", mustCIDR(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || got[0].IP.String() != "192.168.0.53" {
		t.Fatalf("malformed-row handling failed: %+v", got)
	}
}

func TestParseProcNetARP_PopulatesVendor(t *testing.T) {
	// 08:3a:8d is registered to Espressif in the bundled OUI table; verify
	// the parser feeds the same lookup that ARPWorker uses.
	in := `IP address       HW type     Flags       HW address            Mask     Device
192.168.0.139    0x1         0x2         08:3a:8d:8e:3e:f0     *        enp195s0
`
	got := parseProcNetARP(strings.NewReader(in), "enp195s0", mustCIDR(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 {
		t.Fatalf("want 1 update, got %d", len(got))
	}
	if got[0].Vendor == "" {
		t.Errorf("expected non-empty Vendor for known OUI 08:3a:8d, got empty")
	}
}
