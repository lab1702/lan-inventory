// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lab1702/lan-inventory/internal/model"
)

func TestFilterEnterKeepsBufferExitsMode(t *testing.T) {
	m := NewModel(Deps{Subnet: "192.168.1.0/24", Iface: "eth0"})
	m.filterMode = true
	m.filterBuf = "pr"

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mm := updated.(Model)
	if mm.filterMode {
		t.Errorf("Enter should exit filter mode")
	}
	if mm.filterBuf != "pr" {
		t.Errorf("Enter should preserve filter buffer, got %q", mm.filterBuf)
	}
}

func TestFilterEscClearsBufferAndExitsMode(t *testing.T) {
	m := NewModel(Deps{Subnet: "192.168.1.0/24", Iface: "eth0"})
	m.filterMode = true
	m.filterBuf = "pr"

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	mm := updated.(Model)
	if mm.filterMode {
		t.Errorf("Esc should exit filter mode")
	}
	if mm.filterBuf != "" {
		t.Errorf("Esc should clear filter buffer, got %q", mm.filterBuf)
	}
}

func TestEscClearsAppliedFilterWithoutQuitting(t *testing.T) {
	m := NewModel(Deps{Subnet: "192.168.1.0/24", Iface: "eth0"})
	m.filterBuf = "pr"

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	mm := updated.(Model)
	if mm.quitting {
		t.Errorf("Esc with applied filter should clear, not quit")
	}
	if mm.filterBuf != "" {
		t.Errorf("Esc should clear applied filter, got %q", mm.filterBuf)
	}
}

func TestEscQuitsWhenNoFilterApplied(t *testing.T) {
	m := NewModel(Deps{Subnet: "192.168.1.0/24", Iface: "eth0"})

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	mm := updated.(Model)
	if !mm.quitting {
		t.Errorf("Esc with no filter should quit")
	}
}

// Pressing down at the bottom of the list must not let selectedRow drift
// past the last index. Otherwise pressing up doesn't visibly move the
// highlight until the phantom presses are unwound.
func TestDownKeyClampsAtLastRow(t *testing.T) {
	macs := []string{
		"aa:00:00:00:00:01",
		"aa:00:00:00:00:02",
		"aa:00:00:00:00:03",
	}
	devs := make([]*model.Device, len(macs))
	for i, mac := range macs {
		devs[i] = &model.Device{MAC: mac}
	}
	m := NewModel(Deps{})
	m.devices = devs

	for i := 0; i < 10; i++ {
		updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = updated.(Model)
	}
	if want := len(devs) - 1; m.selectedRow != want {
		t.Fatalf("selectedRow ran past last row: got %d, want %d", m.selectedRow, want)
	}

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = updated.(Model)
	if want := len(devs) - 2; m.selectedRow != want {
		t.Fatalf("up press did not move off last row: got %d, want %d", m.selectedRow, want)
	}
}
