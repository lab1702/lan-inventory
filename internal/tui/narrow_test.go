// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lab1702/lan-inventory/internal/model"
)

// Collect exactly the content a user can reach with Down, without duplicating
// overlapping viewport rows or reading directly from a renderer's full output.
func readAllTabRows(t *testing.T, m Model) []string {
	t.Helper()
	m = pressKey(m, tea.KeyHome)
	var rows []string
	for steps := 0; steps < 2048; steps++ {
		visible := contentLines(assertFitsTerminal(t, m))[3:]
		if len(visible) == 0 {
			t.Fatal("expected visible tab content")
		}
		rows = append(rows, visible[0])
		next := pressKey(m, tea.KeyDown)
		if next.scrollRows[m.tab] == m.scrollRows[m.tab] {
			return append(rows, visible[1:]...)
		}
		m = next
	}
	t.Fatal("tab scrolling did not reach its end")
	return nil
}

func TestNarrowEventsExposeEveryRecordField(t *testing.T) {
	for _, width := range []int{20, 40, 120} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			m := NewModel(Deps{})
			m.tab = tabEvents
			for i := 0; i < 5; i++ {
				m.events = append(m.events, model.Event{
					Time: time.Date(2026, 1, 1, 12, 34, i, 0, time.UTC), Type: model.EventUpdated,
					MAC: fmt.Sprintf("aa:bb:cc:dd:ee:%02d", i), IP: net.IPv4(192, 168, 100, byte(200+i)),
				})
			}
			m = updateModel(m, tea.WindowSizeMsg{Width: width, Height: 6})
			rows := readAllTabRows(t, m)
			text := strings.Join(strings.Fields(strings.Join(rows, "\n")), "")
			previous := -1
			for _, event := range m.events {
				for _, field := range []string{event.Time.Format("15:04:05"), event.Type.String(), event.MAC, event.IP.String()} {
					if !strings.Contains(text, field) {
						t.Errorf("event field %q is unreachable at width %d:\n%s", field, width, strings.Join(rows, "\n"))
					}
				}
				position := strings.Index(text, event.MAC)
				if position <= previous {
					t.Fatal("scrolling should retain newest-first event order")
				}
				previous = position
			}
			if width == 120 && len(rows) != len(m.events) {
				t.Fatalf("normal-width events should remain one row each, got %d rows", len(rows))
			}
		})
	}
}

func TestWrappedEventArrivalPreservesScrolledPosition(t *testing.T) {
	m := NewModel(Deps{})
	m.tab = tabEvents
	for i := 0; i < 10; i++ {
		m.events = append(m.events, model.Event{
			MAC: fmt.Sprintf("aa:bb:cc:dd:ee:%02d", i), IP: net.IPv4(192, 168, 100, byte(i+1)),
		})
	}
	m = updateModel(m, tea.WindowSizeMsg{Width: 40, Height: 6})
	for i := 0; i < 3; i++ {
		m = pressKey(m, tea.KeyDown)
	}
	before := contentLines(m.scrollContent(m.viewEvents()))[0]
	oldScroll := m.scrollRows[tabEvents]
	m = updateModel(m, eventMsg{Type: model.EventJoined, Device: &model.Device{
		MAC: "aa:bb:cc:dd:ee:ff", IPs: []net.IP{net.ParseIP("192.168.100.254")},
	}})
	if after := contentLines(m.scrollContent(m.viewEvents()))[0]; after != before {
		t.Fatalf("wrapped arrival moved the reader: before=%q after=%q", before, after)
	}
	if m.scrollRows[tabEvents] <= oldScroll+1 {
		t.Fatal("a wrapped event should advance scroll by all its physical rows")
	}
	m = pressKey(m, tea.KeyHome)
	if view := assertFitsTerminal(t, m); !strings.Contains(view, "192.168.100.254") {
		t.Fatalf("Home should reveal the newest event and its address:\n%s", view)
	}
}

func subnetGridRows(lines []string) []string {
	var rows []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && strings.Trim(line, "_●·x") == "" {
			rows = append(rows, line)
		}
	}
	return rows
}

func TestNarrowSubnetExposesEveryAddressAndLegend(t *testing.T) {
	m := NewModel(Deps{Subnet: "192.168.0.0/22"})
	m.tab = tabSubnet
	m.devices = []*model.Device{
		{IPs: []net.IP{net.ParseIP("192.168.0.31")}, Status: model.StatusOnline},
		{IPs: []net.IP{net.ParseIP("192.168.1.255")}, Status: model.StatusStale},
		{IPs: []net.IP{net.ParseIP("192.168.3.255")}, Status: model.StatusOffline},
	}
	m = updateModel(m, tea.WindowSizeMsg{Width: 20, Height: 8})
	rows := readAllTabRows(t, m)
	grid := []rune(strings.Join(subnetGridRows(rows), ""))
	if len(grid) != 1024 {
		t.Fatalf("scrolling should reach exactly 1024 subnet addresses, got %d", len(grid))
	}
	for offset, glyph := range grid {
		want := '_'
		switch offset {
		case 31:
			want = '●'
		case 511:
			want = '·'
		case 1023:
			want = 'x'
		}
		if glyph != want {
			t.Errorf("address offset %d has glyph %q, want %q", offset, glyph, want)
		}
	}
	text := strings.Join(strings.Fields(strings.Join(rows, "\n")), "")
	for _, want := range []string{"Subnet192.168.0.0/22—1024hosts", "Legend:●online·stalexoffline_unseen"} {
		if !strings.Contains(text, want) {
			t.Errorf("subnet title/legend content %q is unreachable:\n%s", want, strings.Join(rows, "\n"))
		}
	}
}

func TestSubnetRetainsNormalGridDimensions(t *testing.T) {
	for subnet, side := range map[string]int{"192.168.0.0/22": 32, "192.168.1.0/24": 16} {
		m := NewModel(Deps{Subnet: subnet})
		rows := subnetGridRows(contentLines(m.viewSubnet()))
		if len(rows) != side {
			t.Fatalf("%s grid has %d rows, want %d", subnet, len(rows), side)
		}
		for _, row := range rows {
			if len([]rune(row)) != side {
				t.Errorf("%s grid row has %d columns, want %d", subnet, len([]rune(row)), side)
			}
		}
	}
}
