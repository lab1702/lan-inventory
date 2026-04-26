// SPDX-License-Identifier: GPL-2.0-or-later

// Package snapshot renders the scanner's current device map as JSON or as a
// human-readable text table for the --once mode.
package snapshot

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

// Header is the metadata stamped onto a JSON snapshot.
type Header struct {
	ScannedAt time.Time `json:"scanned_at"`
	Subnet    string    `json:"subnet"`
	Iface     string    `json:"interface"`
}

type jsonDoc struct {
	Header
	Devices []*model.Device `json:"devices"`
}

// WriteJSON marshals the header and devices as a single JSON object.
func WriteJSON(w io.Writer, h Header, devices []*model.Device) error {
	doc := jsonDoc{Header: h, Devices: devices}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// WriteTable writes a fixed-width text table. If color is true and the
// underlying writer is a TTY, ANSI color codes are emitted for status.
func WriteTable(w io.Writer, devices []*model.Device, color bool) error {
	sorted := append([]*model.Device(nil), devices...)
	sort.Slice(sorted, func(i, j int) bool {
		return firstIPString(sorted[i]) < firstIPString(sorted[j])
	})

	header := []string{"IP", "MAC", "Vendor", "Hostname", "OS", "Ports", "RTT", "Status"}
	rows := [][]string{header}
	for _, d := range sorted {
		ports := portsCSV(d.OpenPorts)
		rows = append(rows, []string{
			firstIPString(d),
			d.MAC,
			truncate(d.Vendor, 14),
			truncate(d.Hostname, 22),
			truncate(d.OSGuess, 12),
			truncate(ports, 22),
			formatRTT(d.RTT),
			colorStatus(d.Status, color),
		})
	}
	widths := columnWidths(rows)
	for i, row := range rows {
		var b strings.Builder
		for j, cell := range row {
			b.WriteString(padRight(cell, widths[j]))
			if j != len(row)-1 {
				b.WriteString("  ")
			}
		}
		b.WriteString("\n")
		if i == 0 {
			b.WriteString(strings.Repeat("-", sum(widths)+2*(len(widths)-1)))
			b.WriteString("\n")
		}
		if _, err := io.WriteString(w, b.String()); err != nil {
			return err
		}
	}
	return nil
}

func firstIPString(d *model.Device) string {
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

func formatRTT(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return d.Round(100 * time.Microsecond).String()
}

func colorStatus(s model.Status, color bool) string {
	label := s.String()
	if !color {
		return label
	}
	switch s {
	case model.StatusOnline:
		return "\x1b[32m" + label + "\x1b[0m"
	case model.StatusStale:
		return "\x1b[33m" + label + "\x1b[0m"
	case model.StatusOffline:
		return "\x1b[31m" + label + "\x1b[0m"
	}
	return label
}

func columnWidths(rows [][]string) []int {
	if len(rows) == 0 {
		return nil
	}
	w := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, cell := range row {
			if l := visibleLen(cell); l > w[i] {
				w[i] = l
			}
		}
	}
	return w
}

func visibleLen(s string) int {
	out := 0
	in := false
	for _, r := range s {
		if r == 0x1b {
			in = true
			continue
		}
		if in {
			if r == 'm' {
				in = false
			}
			continue
		}
		out++
	}
	return out
}

func padRight(s string, w int) string {
	pad := w - visibleLen(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
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

func sum(xs []int) int {
	s := 0
	for _, x := range xs {
		s += x
	}
	return s
}