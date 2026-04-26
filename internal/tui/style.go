// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/lab1702/lan-inventory/internal/model"
)

// All TUI styles. Use ANSI color names (0–15) so the user's terminal theme
// drives the exact hue. Status colors are deliberately green/yellow/red so
// they read correctly under every common theme (dark, light, Solarized, etc.).
var (
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(8)) // bright black
	styleAccent = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(4)) // blue
	styleWarn   = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(3)) // yellow
	styleErr    = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(9)) // bright red
	styleOK     = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(2)) // green

	styleTabActive   = styleAccent.Bold(true).Underline(true)
	styleTabInactive = styleDim
	styleHeaderRow   = styleBold
	styleSelectedRow = lipgloss.NewStyle().Reverse(true)
)

// styleStatus returns the foreground style appropriate for a Device.Status
// value: green for online, yellow for stale, red for offline.
func styleStatus(s model.Status) lipgloss.Style {
	switch s {
	case model.StatusOnline:
		return styleOK
	case model.StatusStale:
		return styleWarn
	case model.StatusOffline:
		return styleErr
	}
	return lipgloss.NewStyle()
}

// styleEventType returns the foreground style for an Event.Type value: green
// for joined, blue for updated, red for left.
func styleEventType(t model.EventType) lipgloss.Style {
	switch t {
	case model.EventJoined:
		return styleOK
	case model.EventUpdated:
		return styleAccent
	case model.EventLeft:
		return styleErr
	}
	return lipgloss.NewStyle()
}