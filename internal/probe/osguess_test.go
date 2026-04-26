package probe_test

import (
	"testing"

	"github.com/lab1702/lan-inventory/internal/probe"
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
		got := probe.OSGuess(c.ttl)
		if got != c.want {
			t.Errorf("OSGuess(%d) = %q, want %q", c.ttl, got, c.want)
		}
	}
}
