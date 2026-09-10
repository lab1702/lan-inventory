// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"strings"

	"github.com/lab1702/lan-inventory/internal/model"
)

// Leave room for the two-line header, its separator, and an active filter.
func (m Model) contentHeight() int {
	height := m.height - 3
	if m.filterMode || m.filterBuf != "" {
		height -= 2
	}
	return max(0, height)
}

func contentLines(content string) []string {
	return strings.Split(strings.TrimRight(content, "\n"), "\n")
}

func (m Model) tabContent() string {
	switch m.tab {
	case tabServices:
		return m.viewServices()
	case tabSubnet:
		return m.viewSubnet()
	case tabEvents:
		return m.viewEvents()
	}
	return ""
}

func (m Model) scrollContent(content string) string {
	lines := contentLines(content)
	start := min(m.scrollRows[m.tab], max(0, len(lines)-m.contentHeight()))
	end := min(len(lines), start+m.contentHeight())
	return strings.Join(lines[start:end], "\n")
}

// Keep table headings and at least five devices when possible. Details use
// the remaining room; on short terminals the selected row takes priority.
func (m Model) deviceLayout(devices []*model.Device) (headers, rows int, details []string) {
	height := m.contentHeight()
	headers = min(2, max(0, height-1))
	rows = height - headers
	if len(devices) == 0 {
		return headers, rows, nil
	}
	detailBudget := rows - min(5, len(devices))
	if detailBudget >= 3 {
		details = contentLines(detailStrip(devices[min(m.selectedRow, len(devices)-1)]))
		details = details[:min(len(details), detailBudget-1)]
		rows -= len(details) + 1 // separator before details
	}
	return headers, rows, details
}

func (m Model) pageSize() int {
	if m.tab == tabDevices {
		devices := filterDevices(m.devices, m.filterBuf)
		sortDevices(devices)
		_, rows, _ := m.deviceLayout(devices)
		return max(1, rows)
	}
	return max(1, m.contentHeight())
}

func (m *Model) moveRow(delta int) {
	if m.tab == tabDevices {
		m.selectedRow += delta
	} else {
		m.scrollRows[m.tab] += delta
	}
}

func (m *Model) clampViewport() {
	devices := filterDevices(m.devices, m.filterBuf)
	sortDevices(devices)
	m.selectedRow = max(0, min(m.selectedRow, len(devices)-1))
	_, rows, _ := m.deviceLayout(devices)
	rows = max(1, rows)
	start := min(m.scrollRows[tabDevices], max(0, len(devices)-rows))
	if m.selectedRow < start {
		start = m.selectedRow
	} else if m.selectedRow >= start+rows {
		start = m.selectedRow - rows + 1
	}
	m.scrollRows[tabDevices] = max(0, start)
	if m.tab != tabDevices {
		lastStart := max(0, len(contentLines(m.tabContent()))-m.contentHeight())
		m.scrollRows[m.tab] = max(0, min(m.scrollRows[m.tab], lastStart))
	}
}
