package tui

import "strings"

// visibleLen returns the number of printed cells in s, ignoring ANSI escape
// sequences. Use this instead of len() when sizing columns that may contain
// styled content.
func visibleLen(s string) int {
	out, in := 0, false
	for _, r := range s {
		if r == 0x1b {
			in = true
			continue
		}
		if in {
			if r == 'm' {
				in = false
			}
			continue
		}
		out++
	}
	return out
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
