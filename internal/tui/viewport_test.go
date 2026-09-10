// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/lab1702/lan-inventory/internal/model"
)

func updateModel(m Model, msg tea.Msg) Model {
	updated, _ := m.Update(msg)
	return updated.(Model)
}

func pressKey(m Model, key tea.KeyType) Model {
	return updateModel(m, tea.KeyMsg{Type: key})
}

func TestSubnetDistinguishesUnseenAddresses(t *testing.T) {
	m := NewModel(Deps{Subnet: "192.168.1.0/30"})
	grid := func() string {
		return strings.Join(contentLines(m.viewSubnet())[3:], "")
	}
	if got := grid(); strings.Count(got, "_") != 4 || strings.Contains(got, "●") {
		t.Fatalf("empty subnet should contain four unseen cells: %q", got)
	}
	m.devices = []*model.Device{
		{IPs: []net.IP{net.ParseIP("192.168.1.1")}, Status: model.StatusOnline},
		{IPs: []net.IP{net.ParseIP("192.168.1.2")}, Status: model.StatusStale},
		{IPs: []net.IP{net.ParseIP("192.168.1.3")}, Status: model.StatusOffline},
	}
	for _, glyph := range []string{"_", "●", "·", "x"} {
		if got := strings.Count(grid(), glyph); got != 1 {
			t.Errorf("expected one %q cell, got %d in %q", glyph, got, grid())
		}
	}
}

func populatedModel() Model {
	m := NewModel(Deps{Subnet: "192.168.0.0/22", Iface: "eth0"})
	for i := 0; i < 50; i++ {
		m.devices = append(m.devices, &model.Device{
			MAC:      fmt.Sprintf("aa:00:00:00:00:%02x", i),
			IPs:      []net.IP{net.IPv4(192, 168, 0, byte(i+1))},
			Services: []model.ServiceInst{{Type: fmt.Sprintf("_service%02d._tcp", i)}},
		})
		m.events = append(m.events, model.Event{MAC: fmt.Sprintf("event-%02d", i), Time: time.Now()})
	}
	return updateModel(m, tea.WindowSizeMsg{Width: 80, Height: 12})
}

func assertFitsTerminal(t *testing.T, m Model) string {
	t.Helper()
	view := m.View()
	width, height := lipgloss.Size(view)
	if width > m.width || height > m.height {
		t.Fatalf("view %dx%d exceeds terminal %dx%d:\n%s", width, height, m.width, m.height, view)
	}
	if !strings.Contains(contentLines(view)[0], "[1] Devices") {
		t.Fatalf("tab header is not visible at top:\n%s", view)
	}
	return view
}

func TestDeviceViewportKeepsSelectionVisible(t *testing.T) {
	m := populatedModel()
	if view := assertFitsTerminal(t, m); !strings.Contains(view, "> 192.168.0.1 ") {
		t.Fatalf("first device should be visible and selected:\n%s", view)
	}
	m = pressKey(m, tea.KeyEnd)
	if view := assertFitsTerminal(t, m); !strings.Contains(view, "> 192.168.0.50 ") {
		t.Fatalf("last device should be visible and selected:\n%s", view)
	}
	m = pressKey(m, tea.KeyUp)
	if view := assertFitsTerminal(t, m); !strings.Contains(view, "> 192.168.0.49 ") {
		t.Fatalf("up should immediately move the visible selection:\n%s", view)
	}
	m = updateModel(m, tea.WindowSizeMsg{Width: 40, Height: 7})
	if view := assertFitsTerminal(t, m); !strings.Contains(view, "> 192.168.0.49 ") {
		t.Fatalf("resizing should keep the selection visible:\n%s", view)
	}
	m = pressKey(m, tea.KeyHome)
	if m.selectedRow != 0 || m.scrollRows[tabDevices] != 0 {
		t.Fatalf("Home should return to the first device: %+v", m)
	}
	m = pressKey(m, tea.KeyPgDown)
	if m.selectedRow == 0 {
		t.Fatal("PgDown should move to the next page")
	}
	assertFitsTerminal(t, m)
}

func TestOtherTabsScrollWithinTerminal(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tab         tab
		first, last string
	}{
		{"events", tabEvents, "event-00", "event-49"},
		{"services", tabServices, "_service00._tcp", "_service49._tcp"},
		{"subnet", tabSubnet, "●_______________________________", "_______________________________x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := populatedModel()
			if tc.tab == tabSubnet {
				m.devices = []*model.Device{
					{IPs: []net.IP{net.ParseIP("192.168.0.0")}, Status: model.StatusOnline},
					{IPs: []net.IP{net.ParseIP("192.168.3.255")}, Status: model.StatusOffline},
				}
			}
			m.tab = tc.tab
			m = pressKey(m, tea.KeyHome)
			if view := assertFitsTerminal(t, m); !strings.Contains(view, tc.first) || strings.Contains(view, tc.last) {
				t.Fatalf("first page should contain first row but not last:\n%s", view)
			}
			m = pressKey(m, tea.KeyPgDown)
			if m.scrollRows[m.tab] == 0 {
				t.Fatal("PgDown should scroll the current tab")
			}
			m = pressKey(m, tea.KeyEnd)
			if view := assertFitsTerminal(t, m); !strings.Contains(view, tc.last) {
				t.Fatalf("last page should contain last row:\n%s", view)
			}
			m = pressKey(m, tea.KeyHome)
			if view := assertFitsTerminal(t, m); !strings.Contains(view, tc.first) {
				t.Fatalf("Home should return to the first page:\n%s", view)
			}
		})
	}
}

func TestSelectionClampsWhenFilterOrSnapshotShrinks(t *testing.T) {
	m := populatedModel()
	m = pressKey(m, tea.KeyEnd)
	m.filterMode = true
	m = updateModel(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("192.168.0.2")})
	if m.selectedRow != 10 { // .2 and .20 through .29
		t.Fatalf("filter should clamp stored selection to 10, got %d", m.selectedRow)
	}
	m = pressKey(m, tea.KeyEnter)
	m = pressKey(m, tea.KeyUp)
	if m.selectedRow != 9 {
		t.Fatalf("up should immediately move after filtering, got %d", m.selectedRow)
	}
	assertFitsTerminal(t, m)
	m.deps.Snapshot = func() []*model.Device { return m.devices[:3] }
	m = updateModel(m, tickMsg(time.Now()))
	if m.selectedRow != 0 || m.scrollRows[tabDevices] != 0 {
		t.Fatalf("snapshot shrink should reset stored selection and viewport: row=%d scroll=%d", m.selectedRow, m.scrollRows[tabDevices])
	}
	m.filterMode = true
	m = updateModel(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("missing")})
	if m.selectedRow != 0 {
		t.Fatalf("empty filter results should keep selection at zero, got %d", m.selectedRow)
	}
	m = pressKey(m, tea.KeyEsc)
	m = pressKey(m, tea.KeyDown)
	if m.selectedRow != 1 {
		t.Fatalf("navigation after clearing an empty filter should work, got %d", m.selectedRow)
	}
}

func TestEventsFollowNewestUnlessScrolled(t *testing.T) {
	m := populatedModel()
	m.tab = tabEvents
	m = updateModel(m, eventMsg{Device: &model.Device{MAC: "newest"}})
	if m.scrollRows[tabEvents] != 0 || !strings.Contains(assertFitsTerminal(t, m), "newest") {
		t.Fatal("new events should remain visible while at the top")
	}
	m = pressKey(m, tea.KeyDown)
	m = pressKey(m, tea.KeyDown)
	before := contentLines(m.scrollContent(m.viewEvents()))[0]
	m = updateModel(m, eventMsg{Device: &model.Device{MAC: "next"}})
	if after := contentLines(m.scrollContent(m.viewEvents()))[0]; after != before {
		t.Fatalf("new event moved the scrolled reading position: before=%q after=%q", before, after)
	}
	m = pressKey(m, tea.KeyHome)
	if !strings.Contains(assertFitsTerminal(t, m), "next") {
		t.Fatal("Home should reveal the newest event")
	}
}
