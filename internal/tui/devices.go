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
	b.WriteString(fmt.Sprintf("Sort: %s   ", m.sortKey))
	b.WriteString(fmt.Sprintf("Selection: %d/%d\n\n", m.selectedRow+1, len(devices)))

	// Column widths chosen to match the previous fmt.Sprintf("%-15s  %-17s ...") layout.
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
		padRight("IP", wIP),
		padRight("MAC", wMAC),
		padRight("Vendor", wVendor),
		padRight("Hostname", wHost),
		padRight("OS", wOS),
		padRight("Ports", wPorts),
		padRight("RTT", wRTT),
		"Status",
	}
	header := strings.Join(headerCells, "  ")
	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", visibleLen(header)))
	b.WriteString("\n")

	for i, d := range devices {
		marker := "  "
		if i == m.selectedRow {
			marker = "> "
		}
		row := strings.Join([]string{
			padRight(firstIP(d), wIP),
			padRight(d.MAC, wMAC),
			padRight(truncate(d.Vendor, 12), wVendor),
			padRight(truncate(d.Hostname, 22), wHost),
			padRight(truncate(d.OSGuess, 12), wOS),
			padRight(truncate(portsCSV(d.OpenPorts), 22), wPorts),
			padRight(rttString(d.RTT), wRTT),
			d.Status.String(),
		}, "  ")
		b.WriteString(marker)
		b.WriteString(row)
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
	b.WriteString("─── selected ─────────────────────────\n")
	b.WriteString(fmt.Sprintf("MAC:      %s\n", d.MAC))
	b.WriteString(fmt.Sprintf("Vendor:   %s\n", d.Vendor))
	b.WriteString(fmt.Sprintf("OS guess: %s\n", d.OSGuess))
	if len(d.OpenPorts) > 0 {
		ports := make([]string, 0, len(d.OpenPorts))
		for _, p := range d.OpenPorts {
			label := fmt.Sprintf("%d/%s", p.Number, p.Proto)
			if p.Service != "" {
				label += " (" + p.Service + ")"
			}
			ports = append(ports, label)
		}
		b.WriteString("Ports:    " + strings.Join(ports, ", ") + "\n")
	}
	if len(d.Services) > 0 {
		svcs := make([]string, 0, len(d.Services))
		for _, s := range d.Services {
			svcs = append(svcs, fmt.Sprintf("%s %q :%d", s.Type, s.Name, s.Port))
		}
		b.WriteString("Services: " + strings.Join(svcs, "; ") + "\n")
	}
	b.WriteString(fmt.Sprintf("First/Last seen: %s / %s\n",
		d.FirstSeen.Format(time.RFC3339), d.LastSeen.Format(time.RFC3339)))
	if len(d.RTTHistory) > 0 {
		samples := make([]string, 0, len(d.RTTHistory))
		for _, r := range d.RTTHistory {
			samples = append(samples, rttString(r))
		}
		b.WriteString("RTT history: " + strings.Join(samples, " ") + "\n")
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
