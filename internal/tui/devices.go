package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

func (m Model) viewDevices() string {
	if len(m.devices) == 0 {
		return "(no devices yet — first scan in progress)"
	}
	devices := append([]*model.Device(nil), m.devices...)
	sort.Slice(devices, func(i, j int) bool { return firstIP(devices[i]) < firstIP(devices[j]) })

	var b strings.Builder
	header := fmt.Sprintf("%-15s  %-17s  %-12s  %-22s  %-12s  %-22s  %-8s  %s",
		"IP", "MAC", "Vendor", "Hostname", "OS", "Ports", "RTT", "Status")
	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", len(header)))
	b.WriteString("\n")
	for _, d := range devices {
		b.WriteString(fmt.Sprintf("%-15s  %-17s  %-12s  %-22s  %-12s  %-22s  %-8s  %s\n",
			firstIP(d),
			d.MAC,
			truncate(d.Vendor, 12),
			truncate(d.Hostname, 22),
			truncate(d.OSGuess, 12),
			truncate(portsCSV(d.OpenPorts), 22),
			rttString(d.RTT),
			d.Status,
		))
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
