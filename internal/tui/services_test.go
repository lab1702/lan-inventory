// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"fmt"
	"net"
	"reflect"
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
			for i, host := range hosts {
				m.devices = append(m.devices, &model.Device{
					MAC: fmt.Sprintf("02:00:00:00:00:%02x", i), IPs: []net.IP{net.IPv4(192, 168, 1, byte(i+1))},
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

func serviceDevice(mac, ip, hostname string) *model.Device {
	d := &model.Device{
		MAC: mac, Hostname: hostname,
		Services:  []model.ServiceInst{{Type: "_ssh._tcp", Name: "first"}, {Type: "_ssh._tcp", Name: "second"}},
		OpenPorts: []model.Port{{Number: 22, Proto: "tcp", Service: "ssh"}, {Number: 22, Proto: "tcp", Service: "ssh"}},
	}
	if ip != "" {
		d.IPs = []net.IP{net.ParseIP(ip)}
	}
	return d
}

func TestServiceGroupsCountDistinctHostsWithDuplicateNames(t *testing.T) {
	devices := []*model.Device{
		serviceDevice("02:00:00:00:00:02", "192.168.1.20", "nas"),
		serviceDevice("02:00:00:00:00:01", "192.168.1.10", "nas"),
	}
	want := []string{"nas (192.168.1.10)", "nas (192.168.1.20)"}
	groups := groupServices(devices)
	for _, key := range []string{"_ssh._tcp", "22/tcp (ssh)"} {
		if !reflect.DeepEqual(groups[key], want) {
			t.Errorf("%s host labels = %v, want %v", key, groups[key], want)
		}
	}
	reversed := []*model.Device{devices[1], devices[0]}
	if got := groupServices(reversed); !reflect.DeepEqual(got, groups) {
		t.Fatalf("grouping should not depend on snapshot order: %v vs %v", got, groups)
	}
	m := NewModel(Deps{})
	m.devices = devices
	view := m.viewServices()
	if strings.Count(view, "2 hosts") != 2 || strings.Contains(view, "instance") {
		t.Fatalf("counts should describe distinct hosts for both service sources:\n%s", view)
	}
}

func TestServiceGroupsDeduplicateMACAndRepeatedAdvertisements(t *testing.T) {
	a := serviceDevice("02:AA:00:00:00:01", "192.168.1.10", "nas")
	// An mDNS type matching a port label must not count that host twice.
	a.Services = append(a.Services, model.ServiceInst{Type: "22/tcp (ssh)"})
	b := serviceDevice("02:aa:00:00:00:01", "192.168.1.20", "nas")
	groups := groupServices([]*model.Device{a, b})
	for _, key := range []string{"_ssh._tcp", "22/tcp (ssh)"} {
		if want := []string{"nas"}; !reflect.DeepEqual(groups[key], want) {
			t.Errorf("%s should contain one MAC-identified host, got %v", key, groups[key])
		}
	}
	m := NewModel(Deps{})
	m.devices = []*model.Device{a, b}
	if view := m.viewServices(); strings.Count(view, "1 host ") != 2 {
		t.Fatalf("repeated advertisements should count as one host:\n%s", view)
	}
}

func TestServiceGroupsFallBackToIPOrMACWithoutHostname(t *testing.T) {
	devices := []*model.Device{
		serviceDevice("02:00:00:00:00:01", "192.168.1.10", ""),
		serviceDevice("02:00:00:00:00:02", "", ""),
		serviceDevice("", "192.168.1.30", ""),
		serviceDevice("", "192.168.1.30", ""),
	}
	want := []string{"02:00:00:00:00:02", "192.168.1.10", "192.168.1.30"}
	for key, got := range groupServices(devices) {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s unnamed host labels = %v, want %v", key, got, want)
		}
	}
}

func TestServiceGroupsDisambiguateNamesWithoutUniqueAddresses(t *testing.T) {
	for _, ip := range []string{"", "192.168.1.10"} {
		t.Run(ip, func(t *testing.T) {
			macs := []string{"02:00:00:00:00:01", "02:00:00:00:00:02"}
			devices := []*model.Device{serviceDevice(macs[0], ip, "nas"), serviceDevice(macs[1], ip, "nas")}
			for key, labels := range groupServices(devices) {
				if len(labels) != 2 || labels[0] == labels[1] {
					t.Fatalf("%s should retain both distinct endpoints: %v", key, labels)
				}
				for i, label := range labels {
					if !strings.Contains(label, "nas") || !strings.Contains(label, macs[i]) {
						t.Errorf("%s should distinguish host %s by MAC, got %q", key, macs[i], label)
					}
				}
			}
		})
	}
}
