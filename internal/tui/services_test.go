// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/lab1702/lan-inventory/internal/model"
)

func TestServicesWrapBeforeScrolling(t *testing.T) {
	for _, serviceType := range []string{"_http._tcp", strings.Repeat("longservicetype", 8) + "._tcp"} {
		t.Run(serviceType, func(t *testing.T) {
			m := NewModel(Deps{})
			m.tab = tabServices
			hosts := []string{strings.Repeat("verylonghostname", 8) + ".local"}
			for i := 0; i < 6; i++ {
				hosts = append(hosts, fmt.Sprintf("discovered-host-number-%02d.local", i))
			}
			for _, host := range hosts {
				m.devices = append(m.devices, &model.Device{
					Hostname: host, Services: []model.ServiceInst{{Type: serviceType}},
				})
			}
			m = updateModel(m, tea.WindowSizeMsg{Width: 80, Height: 6})
			width, height := lipgloss.Size(m.viewServices())
			if width > 80 || height <= m.contentHeight() {
				t.Fatalf("service group should wrap into scrollable rows, got %dx%d", width, height)
			}
			var displayed []string
			for {
				lines := contentLines(assertFitsTerminal(t, m))[3:]
				displayed = append(displayed, lines[0])
				next := pressKey(m, tea.KeyDown)
				if next.scrollRows[tabServices] == m.scrollRows[tabServices] {
					displayed = append(displayed, lines[1:]...)
					break
				}
				m = next
			}
			text := strings.Join(strings.Fields(strings.Join(displayed, "\n")), "")
			for _, want := range append(hosts, serviceType) {
				if !strings.Contains(text, want) {
					t.Errorf("service content %q was not reachable by scrolling:\n%s", want, strings.Join(displayed, "\n"))
				}
			}
			m = pressKey(m, tea.KeyHome)
			if m.scrollRows[tabServices] != 0 {
				t.Fatal("Home should return to the first wrapped service row")
			}
		})
	}
}
