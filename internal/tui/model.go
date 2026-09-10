// SPDX-License-Identifier: GPL-2.0-or-later

// Package tui implements the Bubble Tea TUI: a 4-tab dashboard over the
// scanner's live device map.
package tui

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

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
	Snapshot func() []*model.Device          // returns a fresh slice each call
	Events   func() <-chan model.DeviceEvent // single-consumer channel of new events
	OnRescan func()                          // optional: called when user presses 'r'
}

// Model is the root Bubble Tea model.
type Model struct {
	deps Deps

	tab     tab
	devices []*model.Device
	events  []model.Event

	width  int
	height int

	pollInterval time.Duration
	quitting     bool

	// Devices-tab interaction state
	filterBuf         string // current filter text
	filterMode        bool   // true while typing filter
	selectedRow       int    // selected device index after sort+filter
	scrollRows        [4]int // first visible row in each tab
	rescanNonce       int    // bumped by 'r' to signal scanner (consumed via Deps.OnRescan)
	showDeviceDetails bool
	detailScroll      int

	// help overlay
	showHelp bool
}

func NewModel(deps Deps) Model {
	return Model{
		deps:         deps,
		tab:          tabDevices,
		pollInterval: 1 * time.Second,
		width:        120,
		height:       24,
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
	previous := m.selectedIdentity()
	next, cmd := m.update(msg)
	_, snapshotTick := msg.(tickMsg)
	identityLost := false
	if (snapshotTick || next.filterBuf != m.filterBuf) && previous.valid() {
		devices := filterDevices(next.devices, next.filterBuf)
		sortDevices(devices)
		if row := previous.find(devices); row >= 0 {
			next.selectedRow = row
		} else {
			identityLost = true
			// A removed or filtered-out device cannot remain open under
			// another device's identity. Return to the nearest list row.
			next.showDeviceDetails = false
		}
	}
	next.clampViewport()
	if identityLost || !previous.matches(next.selectedIdentity()) {
		next.detailScroll = 0
	}
	return next, cmd
}

func (m Model) update(msg tea.Msg) (Model, tea.Cmd) {
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
					_, size := utf8.DecodeLastRuneInString(m.filterBuf)
					m.filterBuf = m.filterBuf[:n-size]
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
		if m.showDeviceDetails && m.tab == tabDevices {
			switch msg.String() {
			case "esc", "enter":
				m.showDeviceDetails = false
				return m, nil
			case "up", "k":
				m.detailScroll--
				return m, nil
			case "down", "j":
				m.detailScroll++
				return m, nil
			case "pgup":
				m.detailScroll -= m.detailPageSize()
				return m, nil
			case "pgdown":
				m.detailScroll += m.detailPageSize()
				return m, nil
			case "home":
				m.detailScroll = 0
				return m, nil
			case "end":
				m.detailScroll = len(m.deviceDetailLines())
				return m, nil
			}
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
			m.showDeviceDetails = false
		case "2":
			m.tab = tabServices
			m.showDeviceDetails = false
		case "3":
			m.tab = tabSubnet
			m.showDeviceDetails = false
		case "4":
			m.tab = tabEvents
			m.showDeviceDetails = false
		case "enter":
			if m.tab == tabDevices && len(filterDevices(m.devices, m.filterBuf)) > 0 {
				m.showDeviceDetails = true
				m.detailScroll = 0
			}
		case "/":
			m.showDeviceDetails = false
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
			m.moveRow(-1)
		case "down", "j":
			m.moveRow(1)
		case "pgup":
			m.moveRow(-m.pageSize())
		case "pgdown":
			m.moveRow(m.pageSize())
		case "home":
			if m.tab == tabDevices {
				m.selectedRow = 0
			}
			m.scrollRows[m.tab] = 0
		case "end":
			if m.tab == tabDevices {
				m.selectedRow = len(m.devices)
			} else {
				m.scrollRows[m.tab] = len(contentLines(m.tabContent()))
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
		// Follow incoming events at the top; preserve the reader's position
		// when they have scrolled into older events.
		if m.scrollRows[tabEvents] > 0 {
			m.scrollRows[tabEvents] += len(contentLines(m.renderEvent(evt)))
		}
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
		return m.fitTerminal(helpText())
	}
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")
	switch m.tab {
	case tabDevices:
		if m.showDeviceDetails {
			b.WriteString(m.viewDeviceDetails())
		} else {
			b.WriteString(m.viewDevices())
		}
	case tabServices:
		b.WriteString(m.scrollContent(m.viewServices()))
	case tabSubnet:
		b.WriteString(m.scrollContent(m.viewSubnet()))
	case tabEvents:
		b.WriteString(m.scrollContent(m.viewEvents()))
	}
	if m.filterMode || m.filterBuf != "" {
		b.WriteString("\n\n")
		b.WriteString(styleWarn.Render(fmt.Sprintf("/filter: %s", m.filterBuf)))
	}
	return m.fitTerminal(b.String())
}

func (m Model) fitTerminal(content string) string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}
	// Bound the width as well, so terminal wrapping cannot push the header
	// or selection out of the height-bounded frame.
	return lipgloss.NewStyle().MaxWidth(m.width).MaxHeight(m.height).Render(content)
}

func helpText() string {
	rows := []struct {
		key  string
		desc string
	}{
		{"1-4", "switch tabs (Devices / Services / Subnet / Events)"},
		{"↑/↓ or k/j", "select devices / scroll the current tab"},
		{"PgUp/PgDn", "move one page"},
		{"Home/End", "first/last row (Home shows newest events)"},
		{"Enter", "open device details / apply a filter; Esc returns"},
		{"● / · / x", "compact device status: online / stale / offline"},
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
