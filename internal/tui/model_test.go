// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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
