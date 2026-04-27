// SPDX-License-Identifier: GPL-2.0-or-later

// Package tui implements the Bubble Tea TUI: a 4-tab dashboard over the
// scanner's live device map.
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lab1702/lan-inventory/internal/model"
)

type tab int

const (
	tabDevices tab = iota
	tabServices
	tabSubnet
	tabEvents
)

// Deps wires runtime dependencies into the TUI. Empty values are tolerated for
// tests; production callers should supply Snapshot/Events.
type Deps struct {
	Subnet   string
	Iface    string
	Snapshot func() []*model.Device                // returns a fresh slice each call
	Events   func() <-chan model.DeviceEvent       // single-consumer channel of new events
	OnRescan func()                                // optional: called when user presses 'r'
}

// Model is the root Bubble Tea model.
type Model struct {
	deps Deps

	tab      tab
	devices  []*model.Device
	events   []model.Event

	width  int
	height int

	pollInterval time.Duration
	quitting     bool

	// Devices-tab interaction state
	filterBuf    string // current filter text
	filterMode   bool   // true while typing filter
	selectedRow  int    // selected device index after sort+filter
	rescanNonce  int    // bumped by 'r' to signal scanner (consumed via Deps.OnRescan)

	// help overlay
	showHelp bool
}

func NewModel(deps Deps) Model {
	return Model{
		deps:         deps,
		tab:          tabDevices,
		pollInterval: 1 * time.Second,
	}
}

// Init starts the snapshot poll ticker and event subscription.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{tickCmd(m.pollInterval)}
	if m.deps.Events != nil {
		cmds = append(cmds, listenEvents(m.deps.Events()))
	}
	return tea.Batch(cmds...)
}

type tickMsg time.Time

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

type eventMsg model.DeviceEvent

func listenEvents(ch <-chan model.DeviceEvent) tea.Cmd {
	return func() tea.Msg {
		e, ok := <-ch
		if !ok {
			return nil
		}
		return eventMsg(e)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		if m.filterMode {
			switch msg.Type {
			case tea.KeyCtrlC:
				m.quitting = true
				return m, tea.Quit
			case tea.KeyEnter:
				m.filterMode = false
			case tea.KeyEsc:
				m.filterMode = false
				m.filterBuf = ""
			case tea.KeyBackspace:
				if n := len(m.filterBuf); n > 0 {
					m.filterBuf = m.filterBuf[:n-1]
				}
			case tea.KeyRunes:
				m.filterBuf += string(msg.Runes)
			}
			return m, nil
		}
		if m.showHelp {
			m.showHelp = false
			return m, nil
		}
		switch msg.String() {
		case "esc":
			if m.filterBuf != "" {
				m.filterBuf = ""
				return m, nil
			}
			m.quitting = true
			return m, tea.Quit
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "1":
			m.tab = tabDevices
		case "2":
			m.tab = tabServices
		case "3":
			m.tab = tabSubnet
		case "4":
			m.tab = tabEvents
		case "/":
			m.filterMode = true
			m.filterBuf = ""
		case "r":
			m.rescanNonce++
			if m.deps.OnRescan != nil {
				m.deps.OnRescan()
			}
		case "?":
			m.showHelp = true
		case "up", "k":
			if m.selectedRow > 0 {
				m.selectedRow--
			}
		case "down", "j":
			n := len(filterDevices(m.devices, m.filterBuf))
			if m.selectedRow < n-1 {
				m.selectedRow++
			}
		}
	case tickMsg:
		if m.deps.Snapshot != nil {
			m.devices = m.deps.Snapshot()
		}
		return m, tickCmd(m.pollInterval)
	case eventMsg:
		evt := model.Event{Time: time.Now(), Type: msg.Type, MAC: msg.Device.MAC}
		if len(msg.Device.IPs) > 0 {
			evt.IP = msg.Device.IPs[0]
		}
		m.events = append([]model.Event{evt}, m.events...)
		if len(m.events) > 200 {
			m.events = m.events[:200]
		}
		if m.deps.Events != nil {
			return m, listenEvents(m.deps.Events())
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	if m.showHelp {
		return helpText()
	}
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")
	switch m.tab {
	case tabDevices:
		b.WriteString(m.viewDevices())
	case tabServices:
		b.WriteString(m.viewServices())
	case tabSubnet:
		b.WriteString(m.viewSubnet())
	case tabEvents:
		b.WriteString(m.viewEvents())
	}
	if m.filterMode || m.filterBuf != "" {
		b.WriteString("\n\n")
		b.WriteString(styleWarn.Render(fmt.Sprintf("/filter: %s", m.filterBuf)))
	}
	return b.String()
}

func helpText() string {
	rows := []struct {
		key  string
		desc string
	}{
		{"1-4", "switch tabs (Devices / Services / Subnet / Events)"},
		{"↑/↓ or k/j", "navigate selection"},
		{"Enter", "(in filter mode) apply the filter"},
		{"/", "start filter (typing narrows the device list; Enter applies)"},
		{"r", "force a rescan now"},
		{"?", "toggle this help"},
		{"q / Esc", "quit"},
	}
	lines := []string{
		styleBold.Render("Help — lan-inventory"),
		"",
	}
	for _, r := range rows {
		lines = append(lines, fmt.Sprintf("  %s  %s", padRight(styleAccent.Render(r.key), 12), r.desc))
	}
	lines = append(lines, "", styleDim.Render("Press any key to dismiss."))
	return strings.Join(lines, "\n")
}

func (m Model) renderHeader() string {
	tabs := []string{"Devices", "Services", "Subnet", "Events"}
	rendered := make([]string, len(tabs))
	for i, name := range tabs {
		label := fmt.Sprintf("[%d] %s", i+1, name)
		if int(m.tab) == i {
			label = styleTabActive.Render(label)
		} else {
			label = styleTabInactive.Render(label)
		}
		rendered[i] = label
	}
	stats := m.summaryLine()
	return strings.Join(rendered, "  ") + "\n" + stats
}

func (m Model) summaryLine() string {
	online, stale, offline := 0, 0, 0
	for _, d := range m.devices {
		switch d.Status {
		case model.StatusOnline:
			online++
		case model.StatusStale:
			stale++
		case model.StatusOffline:
			offline++
		}
	}
	parts := []string{
		styleOK.Render(fmt.Sprintf("Online: %d", online)),
		styleWarn.Render(fmt.Sprintf("Stale: %d", stale)),
		styleErr.Render(fmt.Sprintf("Offline: %d", offline)),
		fmt.Sprintf("Subnet: %s", m.deps.Subnet),
		fmt.Sprintf("Iface: %s", m.deps.Iface),
	}
	return strings.Join(parts, "   ")
}