// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"fmt"
	"strings"
)

func (m Model) viewEvents() string {
	if len(m.events) == 0 {
		return "(no events yet)"
	}
	var b strings.Builder
	for _, e := range m.events {
		ip := ""
		if e.IP != nil {
			ip = e.IP.String()
		}
		t := styleDim.Render(e.Time.Format("15:04:05"))
		typeStr := padRight(styleEventType(e.Type).Render(e.Type.String()), 7)
		b.WriteString(fmt.Sprintf("%s  %s  %-18s  %s\n",
			t,
			typeStr,
			e.MAC,
			ip,
		))
	}
	return b.String()
}