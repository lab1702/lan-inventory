// SPDX-License-Identifier: GPL-2.0-or-later

package netiface_test

import (
	"net"
	"testing"

	"github.com/lab1702/lan-inventory/internal/netiface"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestCheckSubnetSize(t *testing.T) {
	cases := []struct {
		name    string
		subnet  *net.IPNet
		wantErr bool
	}{
		{"slash 24 ok", mustCIDR("192.168.1.0/24"), false},
		{"slash 25 ok", mustCIDR("192.168.1.0/25"), false},
		{"slash 22 ok (boundary)", mustCIDR("10.0.0.0/22"), false},
		{"slash 21 too big", mustCIDR("10.0.0.0/21"), true},
		{"slash 16 too big", mustCIDR("10.0.0.0/16"), true},
		{"slash 8 too big", mustCIDR("10.0.0.0/8"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := netiface.CheckSubnetSize(c.subnet)
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestSubnetIPs(t *testing.T) {
	subnet := mustCIDR("192.168.1.0/30") // .0, .1, .2, .3 — middle two usable
	ips := netiface.SubnetIPs(subnet)
	got := []string{}
	for _, ip := range ips {
		got = append(got, ip.String())
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if len(got) != len(want) {
		t.Fatalf("got %d ips %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("ip[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}