// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// visibleLen returns the number of printed cells in s, ignoring ANSI escape
// sequences. Use this instead of len() when sizing columns that may contain
// styled content.
func visibleLen(s string) int {
	return lipgloss.Width(s)
}

// padRight pads s with spaces on the right until visibleLen(s) == w. ANSI
// escape sequences in s are not counted toward the width.
func padRight(s string, w int) string {
	pad := w - visibleLen(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}
