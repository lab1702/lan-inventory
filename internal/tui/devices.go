// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/oui"
)

func (m Model) viewDevices() string {
	devices := filterDevices(m.devices, m.filterBuf)
	sortDevices(devices)
	if len(devices) == 0 {
		return "(no devices match)"
	}
	var b strings.Builder
	headers, rows, details := m.deviceLayout(devices)

	columns := m.deviceColumns()
	headerCells := make([]string, 0, len(columns))
	for _, col := range columns {
		headerCells = append(headerCells, padRight(styleHeaderRow.Render(col.name), col.width))
	}
	header := "  " + strings.Join(headerCells, "  ")
	if headers > 0 {
		b.WriteString(header)
		b.WriteString("\n")
	}
	if headers > 1 {
		b.WriteString(styleDim.Render(padRight("Enter: details", visibleLen(header))))
		b.WriteString("\n")
	}

	start := m.scrollRows[tabDevices]
	end := min(len(devices), start+rows)
	for i := start; i < end; i++ {
		d := devices[i]
		marker := "  "
		if i == m.selectedRow {
			marker = "> "
		}
		cells := make([]string, 0, len(columns))
		for _, col := range columns {
			value := truncateCells(col.value(d), col.width)
			// Selected rows use plain cells so an inner style reset cannot
			// cancel the reverse style partway through the row.
			if i != m.selectedRow && col.status {
				value = styleStatus(d.Status).Render(value)
			}
			cells = append(cells, padRight(value, col.width))
		}
		line := marker + strings.Join(cells, "  ")
		if i == m.selectedRow {
			line = styleSelectedRow.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(details) > 0 {
		b.WriteString("\n")
		b.WriteString(strings.Join(details, "\n"))
	}
	return strings.TrimRight(b.String(), "\n")
}

type deviceColumn struct {
	name   string
	width  int
	value  func(*model.Device) string
	status bool
}

// IP and status are always first. Other columns appear only when they fit;
// Enter opens the selected device's complete, scrollable details.
func (m Model) deviceColumns() []deviceColumn {
	columns := []deviceColumn{
		{"IP", 15, firstIP, false},
		{"Status", 7, func(d *model.Device) string { return d.Status.String() }, true},
	}
	if m.width < 26 {
		columns[0].width = max(1, m.width-5)
		columns[1] = deviceColumn{"S", 1, func(d *model.Device) string {
			switch d.Status {
			case model.StatusOnline:
				return "●"
			case model.StatusStale:
				return "·"
			case model.StatusOffline:
				return "x"
			default:
				return "?"
			}
		}, true}
		return columns
	}
	used := 26
	optional := []deviceColumn{
		{"MAC", 17, func(d *model.Device) string { return d.MAC }, false},
		{"Hostname", 22, func(d *model.Device) string { return d.Hostname }, false},
		{"Vendor", 12, func(d *model.Device) string { return d.Vendor }, false},
		{"OS", 12, func(d *model.Device) string { return d.OSGuess }, false},
		{"Ports", 22, func(d *model.Device) string { return portsCSV(d.OpenPorts) }, false},
		{"RTT", 8, func(d *model.Device) string { return rttString(d.RTT) }, false},
	}
	for _, col := range optional {
		if used+2+col.width <= m.width {
			columns = append(columns, col)
			used += 2 + col.width
		}
	}
	return columns
}

// Truncate by display cells so wide Unicode text cannot displace a column.
func truncateCells(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if lipgloss.Width(b.String()+string(r)) > width-1 {
			break
		}
		b.WriteRune(r)
	}
	return b.String() + "…"
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

// sortDevices orders by MAC ascending, then by first IP numerically.
// IPs are compared as bytes (To16 normalized) so 192.168.0.2 sorts before
// 192.168.0.10 — string sort would invert that.
func sortDevices(devs []*model.Device) {
	sort.SliceStable(devs, func(i, j int) bool {
		if devs[i].MAC != devs[j].MAC {
			return devs[i].MAC < devs[j].MAC
		}
		var ai, bi []byte
		if len(devs[i].IPs) > 0 {
			ai = devs[i].IPs[0].To16()
		}
		if len(devs[j].IPs) > 0 {
			bi = devs[j].IPs[0].To16()
		}
		return bytes.Compare(ai, bi) < 0
	})
}

func detailStrip(d *model.Device) string {
	var b strings.Builder
	b.WriteString(styleDim.Render("─── selected ─────────────────────────"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("MAC:     "), d.MAC))
	vendor := oui.LookupLong(d.MAC)
	if vendor == "" {
		vendor = d.Vendor
	}
	b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("Vendor:  "), vendor))
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
		seenTime(d.FirstSeen, "unknown"), seenTime(d.LastSeen, "unconfirmed")))
	if len(d.RTTHistory) > 0 {
		samples := make([]string, 0, len(d.RTTHistory))
		for _, r := range d.RTTHistory {
			samples = append(samples, rttString(r))
		}
		b.WriteString(fmt.Sprintf("%s %s\n", styleAccent.Render("RTT history:"), strings.Join(samples, " ")))
	}
	return b.String()
}

func seenTime(t time.Time, unknown string) string {
	if t.IsZero() {
		return unknown
	}
	return t.Format(time.RFC3339)
}

func (m Model) detailPageSize() int {
	return max(1, m.contentHeight()-2)
}

func (m Model) deviceDetailLines() []string {
	devices := filterDevices(m.devices, m.filterBuf)
	sortDevices(devices)
	if len(devices) == 0 {
		return []string{"(no devices match)"}
	}
	d := devices[m.selectedRow]
	ips := make([]string, 0, len(d.IPs))
	for _, ip := range d.IPs {
		ips = append(ips, ip.String())
	}
	content := fmt.Sprintf("IP: %s\nStatus: %s\nHostname: %s\nRTT: %s\n",
		strings.Join(ips, ", "), d.Status.String(), d.Hostname, rttString(d.RTT))
	content += strings.Join(contentLines(detailStrip(d))[1:], "\n")
	// Wrapping before vertical scrolling makes every field, including long
	// names and service lists, readable even in a narrow terminal.
	return contentLines(lipgloss.NewStyle().Width(max(1, m.width)).Render(content))
}

func (m Model) viewDeviceDetails() string {
	lines := m.deviceDetailLines()
	end := min(len(lines), m.detailScroll+m.detailPageSize())
	return styleBold.Render("Details: Esc back; ↑/↓ scroll") + "\n\n" +
		strings.Join(lines[m.detailScroll:end], "\n")
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
