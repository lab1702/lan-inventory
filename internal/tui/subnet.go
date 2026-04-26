package tui

import (
	"fmt"
	"net"
	"strings"

	"github.com/lab1702/lan-inventory/internal/model"
)

// viewSubnet renders the live subnet as a grid. For a /24, 16×16. For smaller
// subnets the grid auto-shrinks. For larger subnets up to /22, multiple /24
// blocks are stacked vertically.
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
	gridSide := 1 << (hostBits / 2)
	if gridSide < 1 {
		gridSide = 1
	}
	gridOther := 1 << (hostBits - hostBits/2)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Subnet %s — %d hosts\n", m.deps.Subnet, 1<<hostBits))
	b.WriteString("Legend: ● online · stale x offline _ unseen\n\n")

	base := subnet.IP.Mask(subnet.Mask).To4()
	for row := 0; row < gridOther; row++ {
		for col := 0; col < gridSide; col++ {
			offset := row*gridSide + col
			ip := make(net.IP, 4)
			copy(ip, base)
			carry := offset
			for i := 3; i >= 0 && carry > 0; i-- {
				sum := int(ip[i]) + carry
				ip[i] = byte(sum & 0xff)
				carry = sum >> 8
			}
			glyph := "_"
			switch statusByLast[ip.String()] {
			case model.StatusOnline:
				glyph = "●"
			case model.StatusStale:
				glyph = "·"
			case model.StatusOffline:
				glyph = "x"
			}
			b.WriteString(glyph)
		}
		b.WriteString("\n")
	}
	return b.String()
}
