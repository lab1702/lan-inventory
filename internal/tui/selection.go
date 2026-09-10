// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"strings"

	"github.com/lab1702/lan-inventory/internal/model"
)

// Capture values before requesting the next snapshot. A known MAC remains
// authoritative even when addresses change or get reassigned to other hosts.
type deviceIdentity struct {
	mac string
	ips []string
}

func identityOf(d *model.Device) deviceIdentity {
	identity := deviceIdentity{mac: strings.ToLower(d.MAC)}
	for _, ip := range d.IPs {
		if ip != nil {
			identity.ips = append(identity.ips, ip.String())
		}
	}
	return identity
}

func (m Model) selectedIdentity() deviceIdentity {
	devices := filterDevices(m.devices, m.filterBuf)
	sortDevices(devices)
	if m.selectedRow < 0 || m.selectedRow >= len(devices) {
		return deviceIdentity{}
	}
	return identityOf(devices[m.selectedRow])
}

func (id deviceIdentity) valid() bool {
	return id.mac != "" || len(id.ips) > 0
}

// An IP-only observation may acquire a MAC. Once known, that MAC must match;
// overlapping IPs alone cannot move selection to a different known owner.
func (id deviceIdentity) matches(next deviceIdentity) bool {
	if id.mac != "" {
		return id.mac == next.mac
	}
	for _, oldIP := range id.ips {
		for _, newIP := range next.ips {
			if oldIP == newIP {
				return true
			}
		}
	}
	return false
}

func (id deviceIdentity) find(devices []*model.Device) int {
	match := -1
	for i, d := range devices {
		next := identityOf(d)
		if !id.matches(next) {
			continue
		}
		if id.mac != "" || next.mac == "" {
			return i
		}
		// More than one known owner sharing an IP is ambiguous. Do not
		// choose a MAC for an IP-only selection based on sort order.
		if match >= 0 {
			return -1
		}
		match = i
	}
	return match
}
