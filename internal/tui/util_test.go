// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import "testing"

func TestVisibleLen(t *testing.T) {
	cases := []struct {
		s    string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"\x1b[32monline\x1b[0m", 6},
		{"\x1b[31m\x1b[1mERR\x1b[0m", 3},
		{"\x1b[2;32mboth\x1b[0m", 4},
	}
	for _, c := range cases {
		if got := visibleLen(c.s); got != c.want {
			t.Errorf("visibleLen(%q) = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestPadRight(t *testing.T) {
	cases := []struct {
		s    string
		w    int
		want string
	}{
		{"", 3, "   "},
		{"ab", 5, "ab   "},
		{"abc", 3, "abc"},
		{"abcd", 3, "abcd"},
		{"\x1b[32mok\x1b[0m", 5, "\x1b[32mok\x1b[0m   "},
	}
	for _, c := range cases {
		if got := padRight(c.s, c.w); got != c.want {
			t.Errorf("padRight(%q, %d) = %q, want %q", c.s, c.w, got, c.want)
		}
	}
}