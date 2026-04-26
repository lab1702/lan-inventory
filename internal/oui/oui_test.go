// SPDX-License-Identifier: GPL-2.0-or-later

package oui_test

import (
	"testing"

	"github.com/lab1702/lan-inventory/internal/oui"
)

func TestLookupKnown(t *testing.T) {
	cases := []struct {
		mac  string
		want string
	}{
		{"00:1b:63:aa:bb:cc", "Apple"},
		{"00:1B:63:AA:BB:CC", "Apple"},
		{"b8:27:eb:11:22:33", "RaspberryPiF"},
		{"a4:c3:f0:11:22:33", "Intel"},
	}
	for _, c := range cases {
		got := oui.Lookup(c.mac)
		if got != c.want {
			t.Errorf("Lookup(%q) = %q, want %q", c.mac, got, c.want)
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	cases := []string{
		"",
		"not-a-mac",
		"ff:ff:ff:ff:ff:ff",
		"01:02:03:04:05:06",
	}
	for _, c := range cases {
		if got := oui.Lookup(c); got != "" {
			t.Errorf("Lookup(%q) = %q, want empty", c, got)
		}
	}
}