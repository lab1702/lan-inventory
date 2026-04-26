// Package tui implements the Bubble Tea TUI: a 4-tab dashboard over the
// scanner's live device map.
package tui

import (
	"fmt"
	"strings"
	"time"

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
	Snapshot func() []*model.Device                // returns a fresh slice each call
	Events   func() <-chan model.DeviceEvent       // single-consumer channel of new events
}

// Model is the root Bubble Tea model.
type Model struct {
	deps Deps

	tab     tab
	devices []*model.Device
	events  []model.Event

	width  int
	height int

	// pollInterval controls how often the TUI re-snapshots the scanner.
	pollInterval time.Duration

	// for tests: explicitly track quit
	quitting bool
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
		switch msg.String() {
		case "q", "esc", "ctrl+c":
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
	return b.String()
}

func (m Model) renderHeader() string {
	tabs := []string{"Devices", "Services", "Subnet", "Events"}
	rendered := make([]string, len(tabs))
	for i, name := range tabs {
		label := fmt.Sprintf("[%d] %s", i+1, name)
		if int(m.tab) == i {
			label = lipgloss.NewStyle().Bold(true).Underline(true).Render(label)
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
	return fmt.Sprintf("Online: %d   Stale: %d   Offline: %d   Subnet: %s   Iface: %s",
		online, stale, offline, m.deps.Subnet, m.deps.Iface)
}
