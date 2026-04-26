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
		b.WriteString(fmt.Sprintf("%s  %-7s  %-18s  %s\n",
			e.Time.Format("15:04:05"),
			e.Type,
			e.MAC,
			ip,
		))
	}
	return b.String()
}
