// SPDX-License-Identifier: GPL-2.0-or-later

package netiface

import (
	"errors"
	"net"
	"testing"
)

func TestInfoSelectsDefaultGatewaySubnet(t *testing.T) {
	for _, first := range []string{"10.20.30.5/24", "10.20.30.5/16", "192.168.2.5/16"} {
		t.Run(first, func(t *testing.T) {
			var addrs []net.Addr
			for _, cidr := range []string{"fe80::1/64", first, "192.168.1.20/24"} {
				ip, addr, err := net.ParseCIDR(cidr)
				if err != nil {
					t.Fatal(err)
				}
				addr.IP = ip
				addrs = append(addrs, addr)
			}
			got, err := infoForAddresses("test0", addrs, net.ParseIP("192.168.1.1"))
			if err != nil {
				t.Fatal(err)
			}
			if got.HostIP.String() != "192.168.1.20" || got.Subnet.String() != "192.168.1.0/24" {
				t.Fatalf("selected wrong route address: %+v", got)
			}
		})
	}
}

func TestInfoOnLinkFallbackAndSizeLimit(t *testing.T) {
	ip, addr, _ := net.ParseCIDR("192.168.1.20/24")
	addr.IP = ip
	for _, gateway := range []net.IP{nil, net.IPv4zero, net.ParseIP("10.0.0.1")} {
		got, err := infoForAddresses("test0", []net.Addr{addr}, gateway)
		if err != nil || !got.HostIP.Equal(ip) {
			t.Fatalf("on-link fallback = %+v, %v", got, err)
		}
	}
	_, large, _ := net.ParseCIDR("10.0.0.1/16")
	if _, err := infoForAddresses("test0", []net.Addr{large}, net.ParseIP("10.0.0.254")); !errors.Is(err, ErrSubnetTooLarge) {
		t.Fatalf("size guard bypassed: %v", err)
	}
	_, v6, _ := net.ParseCIDR("fe80::1/64")
	if _, err := infoForAddresses("test0", []net.Addr{v6}, nil); err == nil {
		t.Fatal("accepted interface without IPv4")
	}
}
