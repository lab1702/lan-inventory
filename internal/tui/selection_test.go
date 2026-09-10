// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"net"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lab1702/lan-inventory/internal/model"
)

func selectionDevice(mac, ip, hostname string) *model.Device {
	return &model.Device{MAC: mac, IPs: []net.IP{net.ParseIP(ip)}, Hostname: hostname}
}

func selectionDetails(devices []*model.Device, row int) Model {
	m := NewModel(Deps{})
	m.devices = devices
	m = updateModel(m, tea.WindowSizeMsg{Width: 80, Height: 10})
	m.selectedRow = row
	m = pressKey(m, tea.KeyEnter)
	m = pressKey(m, tea.KeyDown)
	return pressKey(m, tea.KeyDown)
}

func snapshotModel(m Model, devices []*model.Device) Model {
	m.deps.Snapshot = func() []*model.Device { return devices }
	return updateModel(m, tickMsg(time.Now()))
}

func TestSnapshotKeepsSelectedMACAcrossInsertionAndAddressChange(t *testing.T) {
	b := selectionDevice("bb:00:00:00:00:01", "192.168.1.2", "selected")
	c := selectionDevice("cc:00:00:00:00:01", "192.168.1.3", "other")
	m := selectionDetails([]*model.Device{b, c}, 0)
	scroll := m.detailScroll
	m = snapshotModel(m, []*model.Device{
		c,
		selectionDevice("aa:00:00:00:00:01", "192.168.1.1", "inserted"),
		selectionDevice(b.MAC, "192.168.1.200", "selected"),
	})
	if m.selectedRow != 1 || m.selectedIdentity().mac != b.MAC {
		t.Fatalf("snapshot insertion moved selected device: row=%d identity=%+v", m.selectedRow, m.selectedIdentity())
	}
	if !m.showDeviceDetails || scroll == 0 || m.detailScroll != scroll {
		t.Fatalf("same device should keep details open at its scroll position: open=%v scroll=%d want=%d", m.showDeviceDetails, m.detailScroll, scroll)
	}
	assertFitsTerminal(t, m)
}

func TestSnapshotFollowsIPOnlyDeviceWhenMACBecomesKnown(t *testing.T) {
	ipOnly := selectionDevice("", "192.168.1.20", "selected")
	a := selectionDevice("aa:00:00:00:00:01", "192.168.1.1", "other")
	m := selectionDetails([]*model.Device{ipOnly, a}, 0)
	scroll := m.detailScroll
	m = snapshotModel(m, []*model.Device{
		a, selectionDevice("bb:00:00:00:00:01", "192.168.1.20", "selected"),
	})
	if m.selectedRow != 1 || m.selectedIdentity().mac != "bb:00:00:00:00:01" {
		t.Fatalf("selection did not follow the IP-only device's MAC promotion: row=%d identity=%+v", m.selectedRow, m.selectedIdentity())
	}
	if !m.showDeviceDetails || m.detailScroll != scroll {
		t.Fatal("MAC promotion should preserve the open device details")
	}
}

func TestSnapshotDoesNotFollowReassignedIPToAnotherMAC(t *testing.T) {
	b := selectionDevice("bb:00:00:00:00:01", "192.168.1.20", "selected")
	m := selectionDetails([]*model.Device{b}, 0)
	a := selectionDevice("aa:00:00:00:00:01", "192.168.1.1", "nearest row")
	m = snapshotModel(m, []*model.Device{
		a, selectionDevice("cc:00:00:00:00:01", "192.168.1.20", "replacement IP owner"),
	})
	if m.selectedRow != 0 || m.selectedIdentity().mac != a.MAC {
		t.Fatalf("known MAC selection followed a reassigned IP: row=%d identity=%+v", m.selectedRow, m.selectedIdentity())
	}
	if m.showDeviceDetails || m.detailScroll != 0 {
		t.Fatal("disappearing device should close details and reset scroll")
	}
}

func TestRemovedSelectionClampsToRemainingDeviceOrEmptyList(t *testing.T) {
	a := selectionDevice("aa:00:00:00:00:01", "192.168.1.1", "remaining")
	b := selectionDevice("bb:00:00:00:00:01", "192.168.1.2", "removed")
	m := selectionDetails([]*model.Device{a, b}, 1)
	m = snapshotModel(m, []*model.Device{a})
	if m.selectedRow != 0 || m.selectedIdentity().mac != a.MAC || m.showDeviceDetails || m.detailScroll != 0 {
		t.Fatal("removed final row should select the remaining device and leave details")
	}
	m = pressKey(m, tea.KeyEnter)
	m = snapshotModel(m, nil)
	if m.selectedRow != 0 || m.selectedIdentity().valid() || m.showDeviceDetails || m.detailScroll != 0 {
		t.Fatal("empty snapshot should clear device selection and details")
	}
	assertFitsTerminal(t, m)
}

func TestFilterPreservesMatchingIdentityAndResetsRemovedSelection(t *testing.T) {
	a := selectionDevice("aa:00:00:00:00:01", "192.168.1.1", "other")
	b := selectionDevice("bb:00:00:00:00:01", "192.168.1.2", "keep-first")
	c := selectionDevice("cc:00:00:00:00:01", "192.168.1.3", "keep-selected")
	m := selectionDetails([]*model.Device{a, b, c}, 2)
	m = updateModel(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	m = updateModel(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("keep")})
	if m.selectedRow != 1 || m.selectedIdentity().mac != c.MAC {
		t.Fatal("filter should retain the selected device when it still matches")
	}
	m = pressKey(m, tea.KeyEnter)
	m = pressKey(m, tea.KeyEnter)
	m = pressKey(m, tea.KeyDown)
	m = snapshotModel(m, []*model.Device{a, b, selectionDevice(c.MAC, "192.168.1.3", "renamed")})
	if m.selectedRow != 0 || m.selectedIdentity().mac != b.MAC || m.detailScroll != 0 || m.showDeviceDetails {
		t.Fatal("selected device leaving filter results should return to the remaining row")
	}
	m = updateModel(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	m = updateModel(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("no match")})
	if m.selectedRow != 0 || m.selectedIdentity().valid() || m.detailScroll != 0 {
		t.Fatal("filter with no matches should clear selection and scroll")
	}
}
