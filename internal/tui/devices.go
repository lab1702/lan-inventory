// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

func (m Model) viewDevices() string {
	devices := filterDevices(m.devices, m.filterBuf)
	sortDevices(devices, m.sortKey)
	if len(devices) == 0 {
		return "(no devices match)"
	}
	if m.selectedRow >= len(devices) {
		m.selectedRow = len(devices) - 1
	}

	var b strings.Builder
	b.WriteString(styleDim.Render(fmt.Sprintf("Sort: %s   Selection: %d/%d", m.sortKey, m.selectedRow+1, len(devices))))
	b.WriteString("\n\n")

	const (
		wIP     = 15
		wMAC    = 17
		wVendor = 12
		wHost   = 22
		wOS     = 12
		wPorts  = 22
		wRTT    = 8
	)
	headerCells := []string{
		padRight(styleHeaderRow.Render("IP"), wIP),
		padRight(styleHeaderRow.Render("MAC"), wMAC),
		padRight(styleHeaderRow.Render("Vendor"), wVendor),
		padRight(styleHeaderRow.Render("Hostname"), wHost),
		padRight(styleHeaderRow.Render("OS"), wOS),
		padRight(styleHeaderRow.Render("Ports"), wPorts),
		padRight(styleHeaderRow.Render("RTT"), wRTT),
		styleHeaderRow.Render("Status"),
	}
	header := strings.Join(headerCells, "  ")
	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(styleDim.Render(strings.Repeat("-", visibleLen(header))))
	b.WriteString("\n")

	for i, d := range devices {
		marker := "  "
		if i == m.selectedRow {
			marker = "> "
		}
		// Compute the un-styled cell content once. Padding and per-cell
		// styling depend on whether this row is selected: selected rows
		// must be plain (no inner ANSI) so styleSelectedRow's Reverse
		// attribute applies uniformly across the whole line — inner
		// resets in styled cells would clobber it mid-row.
		ipCell := firstIP(d)
		macCell := d.MAC
		vendorCell := truncate(d.Vendor, 12)
		hostCell := truncate(d.Hostname, 22)
		osCell := truncate(d.OSGuess, 12)
		portsCell := truncate(portsCSV(d.OpenPorts), 22)
		rttCell := rttString(d.RTT)
		statusCell := d.Status.String()

		var line string
		if i == m.selectedRow {
			cells := []string{
				padRight(ipCell, wIP),
				padRight(macCell, wMAC),
				padRight(vendorCell, wVendor),
				padRight(hostCell, wHost),
				padRight(osCell, wOS),
				padRight(portsCell, wPorts),
				padRight(rttCell, wRTT),
				statusCell,
			}
			line = styleSelectedRow.Render(marker + strings.Join(cells, "  "))
		} else {
			cells := []string{
				padRight(ipCell, wIP),
				padRight(macCell, wMAC),
				padRight(dimIfEmpty(vendorCell), wVendor),
				padRight(dimIfEmpty(hostCell), wHost),
				padRight(dimIfEmpty(osCell), wOS),
				padRight(dimIfEmpty(portsCell), wPorts),
				padRight(rttCell, wRTT),
				styleStatus(d.Status).Render(statusCell),
			}
			line = marker + strings.Join(cells, "  ")
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(devices) > 0 {
		b.WriteString("\n")
		b.WriteString(detailStrip(devices[m.selectedRow]))
	}
	return b.String()
}

func filterDevices(in []*model.Device, q string) []*model.Device {
	out := make([]*model.Device, 0, len(in))
	q = strings.ToLower(q)
	for _, d := range in {
		if q == "" || matchesFilter(d, q) {
			out = append(out, d)
		}
	}
	return out
}

func matchesFilter(d *model.Device, q string) bool {
	if strings.Contains(strings.ToLower(d.Hostname), q) {
		return true
	}
	if strings.Contains(strings.ToLower(d.MAC), q) {
		return true
	}
	if strings.Contains(strings.ToLower(d.Vendor), q) {
		return true
	}
	for _, ip := range d.IPs {
		if strings.Contains(ip.String(), q) {
			return true
		}
	}
	return false
}

func sortDevices(devs []*model.Device, key sortKey) {
	sort.SliceStable(devs, func(i, j int) bool {
		switch key {
		case sortByMAC:
			return devs[i].MAC < devs[j].MAC
		case sortByIP:
			return firstIP(devs[i]) < firstIP(devs[j])
		case sortByHostname:
			return devs[i].Hostname < devs[j].Hostname
		case sortByVendor:
			return devs[i].Vendor < devs[j].Vendor
		case sortByRTT:
			return devs[i].RTT < devs[j].RTT
		case sortByLastSeen:
			return devs[i].LastSeen.After(devs[j].LastSeen)
		}
		return false
	})
}

func detailStrip(d *model.Device) string {
	var b strings.Builder
	b.WriteString(styleDim.Render("─── selected ─────────────────────────"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("MAC:     "), d.MAC))
	b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("Vendor:  "), d.Vendor))
	b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("OS guess:"), d.OSGuess))
	if len(d.OpenPorts) > 0 {
		ports := make([]string, 0, len(d.OpenPorts))
		for _, p := range d.OpenPorts {
			label := fmt.Sprintf("%d/%s", p.Number, p.Proto)
			if p.Service != "" {
				label += " (" + p.Service + ")"
			}
			ports = append(ports, label)
		}
		b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("Ports:   "), strings.Join(ports, ", ")))
	}
	if len(d.Services) > 0 {
		svcs := make([]string, 0, len(d.Services))
		for _, s := range d.Services {
			svcs = append(svcs, fmt.Sprintf("%s %q :%d", s.Type, s.Name, s.Port))
		}
		b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("Services:"), strings.Join(svcs, "; ")))
	}
	b.WriteString(fmt.Sprintf("%s %s / %s\n",
		styleAccent.Render("First/Last seen:"),
		d.FirstSeen.Format(time.RFC3339), d.LastSeen.Format(time.RFC3339)))
	if len(d.RTTHistory) > 0 {
		samples := make([]string, 0, len(d.RTTHistory))
		for _, r := range d.RTTHistory {
			samples = append(samples, rttString(r))
		}
		b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("RTT history:"), strings.Join(samples, " ")))
	}
	return b.String()
}

func firstIP(d *model.Device) string {
	if len(d.IPs) == 0 {
		return ""
	}
	return d.IPs[0].String()
}

func portsCSV(ports []model.Port) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p.Number))
	}
	return strings.Join(parts, ",")
}

func rttString(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return d.Round(100 * time.Microsecond).String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

// dimIfEmpty returns styleDim-rendered s when s is empty, "—", or "--".
// Otherwise returns s unchanged.
func dimIfEmpty(s string) string {
	if s == "" || s == "—" || s == "--" {
		return styleDim.Render(s)
	}
	return s
}