// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/lab1702/lan-inventory/internal/model"
)

func (m Model) viewEvents() string {
	if len(m.events) == 0 {
		return "(no events yet)"
	}
	rows := make([]string, 0, len(m.events))
	for _, e := range m.events {
		rows = append(rows, m.renderEvent(e))
	}
	return strings.Join(rows, "\n")
}

func (m Model) renderEvent(e model.Event) string {
	ip := ""
	if e.IP != nil {
		ip = e.IP.String()
	}
	t := styleDim.Render(e.Time.Format("15:04:05"))
	typeStr := padRight(styleEventType(e.Type).Render(e.Type.String()), 7)
	row := fmt.Sprintf("%s  %s  %-18s  %s", t, typeStr, e.MAC, ip)
	// Wrap before vertical scrolling so the IP remains reachable when the
	// timestamp, event type, and MAC consume the first terminal line.
	return lipgloss.NewStyle().Width(max(1, m.width)).Render(strings.TrimRight(row, " "))
}
