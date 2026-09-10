// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"fmt"
	"net"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/lab1702/lan-inventory/internal/model"
)

// viewSubnet renders the live subnet as a grid. For a /24, 16×16. For smaller
// subnets the grid auto-shrinks; larger subnets up to /22 use a wider grid.
// Narrow terminals reduce the columns and add rows, preserving every address.
func (m Model) viewSubnet() string {
	_, subnet, err := net.ParseCIDR(m.deps.Subnet)
	if err != nil || subnet == nil {
		return "(no subnet info)"
	}
	statusByLast := map[string]model.Status{}
	for _, d := range m.devices {
		for _, ip := range d.IPs {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if subnet.Contains(ip4) {
				statusByLast[ip4.String()] = d.Status
			}
		}
	}

	ones, _ := subnet.Mask.Size()
	if ones < 22 {
		return "(subnet too large to render)"
	}
	hostBits := 32 - ones
	hostCount := 1 << hostBits
	gridSide := min(1<<(hostBits/2), max(1, m.width))
	gridOther := (hostCount + gridSide - 1) / gridSide

	var b strings.Builder
	intro := fmt.Sprintf("Subnet %s — %d hosts\n", m.deps.Subnet, hostCount) +
		styleDim.Render("Legend: ● online · stale x offline _ unseen")
	b.WriteString(lipgloss.NewStyle().Width(max(1, m.width)).Render(intro))
	b.WriteString("\n\n")

	base := subnet.IP.Mask(subnet.Mask).To4()
	for row := 0; row < gridOther; row++ {
		for col := 0; col < gridSide; col++ {
			offset := row*gridSide + col
			if offset >= hostCount {
				break
			}
			ip := make(net.IP, 4)
			copy(ip, base)
			carry := offset
			for i := 3; i >= 0 && carry > 0; i-- {
				sum := int(ip[i]) + carry
				ip[i] = byte(sum & 0xff)
				carry = sum >> 8
			}
			if status, seen := statusByLast[ip.String()]; seen {
				b.WriteString(coloredGlyph(status))
			} else {
				b.WriteString(styleDim.Render("_"))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func coloredGlyph(s model.Status) string {
	switch s {
	case model.StatusOnline:
		return styleOK.Render("●")
	case model.StatusStale:
		return styleWarn.Render("·")
	case model.StatusOffline:
		return styleErr.Render("x")
	}
	return styleDim.Render("_")
}
