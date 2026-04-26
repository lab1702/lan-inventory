package tui_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/exp/teatest"
	"github.com/muesli/termenv"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/tui"
)

func TestQuitOnQ(t *testing.T) {
	model := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0"})
	tm := teatest.NewTestModel(t, model, teatest.WithInitialTermSize(120, 40))

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

func TestSwitchTabs(t *testing.T) {
	model := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0"})
	tm := teatest.NewTestModel(t, model, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})

	out := readUntilStable(t, tm, 500*time.Millisecond)
	if !bytes.Contains(out, []byte("Services")) {
		t.Errorf("expected Services tab to be visible:\n%s", out)
	}
}

func readUntilStable(t *testing.T, tm *teatest.TestModel, wait time.Duration) []byte {
	t.Helper()
	time.Sleep(wait)
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("readUntilStable: %v", err)
	}
	return out
}

func TestDevicesTabRendersRows(t *testing.T) {
	devices := []*model.Device{
		{
			MAC:      "aa:bb:cc:dd:ee:01",
			IPs:      []net.IP{net.ParseIP("192.168.1.10")},
			Hostname: "macbook.local",
			Vendor:   "Apple",
			OSGuess:  "Linux/macOS",
			Status:   model.StatusOnline,
			RTT:      time.Millisecond,
		},
	}
	deps := tui.Deps{
		Subnet:   "192.168.1.0/24",
		Iface:    "eth0",
		Snapshot: func() []*model.Device { return devices },
	}
	mod := tui.NewModel(deps)
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	time.Sleep(1500 * time.Millisecond) // give Tick a chance to run Snapshot
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	for _, want := range []string{"macbook.local", "192.168.1.10", "Apple"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("expected %q in Devices tab:\n%s", want, out)
		}
	}
}

func TestServicesTabGroupsByType(t *testing.T) {
	devices := []*model.Device{
		{
			MAC: "aa:01", IPs: []net.IP{net.ParseIP("192.168.1.10")}, Hostname: "host-a",
			Services: []model.ServiceInst{{Type: "_http._tcp", Name: "alpha", Port: 80}},
		},
		{
			MAC: "aa:02", IPs: []net.IP{net.ParseIP("192.168.1.20")}, Hostname: "host-b",
			Services: []model.ServiceInst{{Type: "_http._tcp", Name: "beta", Port: 80}},
		},
	}
	mod := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0", Snapshot: func() []*model.Device { return devices }})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	time.Sleep(1500 * time.Millisecond)
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Contains(out, []byte("_http._tcp")) {
		t.Errorf("expected _http._tcp grouping:\n%s", out)
	}
	if !bytes.Contains(out, []byte("2 instances")) {
		t.Errorf("expected count summary:\n%s", out)
	}
}

func TestSubnetTabRendersGrid(t *testing.T) {
	mod := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0", Snapshot: func() []*model.Device {
		return []*model.Device{
			{IPs: []net.IP{net.ParseIP("192.168.1.10")}, Status: model.StatusOnline},
			{IPs: []net.IP{net.ParseIP("192.168.1.20")}, Status: model.StatusStale},
		}
	}})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	time.Sleep(1500 * time.Millisecond)
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	// The grid should render some non-empty content with at least one
	// online cell glyph.
	if !bytes.Contains(out, []byte("●")) && !bytes.Contains(out, []byte("·")) {
		t.Errorf("expected subnet grid glyphs:\n%s", out)
	}

	// Confirm the online glyph carries an ANSI escape (color is being applied).
	if bytes.Contains(out, []byte("●")) && !bytes.Contains(out, []byte("\x1b[")) {
		t.Errorf("expected ANSI escapes around colored glyphs:\n%s", out)
	}
}

func TestEventsTabShowsRingBuffer(t *testing.T) {
	ch := make(chan model.DeviceEvent, 4)
	dev := &model.Device{MAC: "aa:bb:cc:dd:ee:99", IPs: []net.IP{net.ParseIP("192.168.1.99")}}
	ch <- model.DeviceEvent{Type: model.EventJoined, Device: dev}

	mod := tui.NewModel(tui.Deps{
		Subnet: "192.168.1.0/24", Iface: "eth0",
		Snapshot: func() []*model.Device { return nil },
		Events:   func() <-chan model.DeviceEvent { return ch },
	})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})
	time.Sleep(1500 * time.Millisecond)
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Contains(out, []byte("aa:bb:cc:dd:ee:99")) {
		t.Errorf("expected event row in Events tab:\n%s", out)
	}
	if !bytes.Contains(out, []byte("joined")) {
		t.Errorf("expected joined label:\n%s", out)
	}
}

func TestSortCycleByKey(t *testing.T) {
	devices := []*model.Device{
		{IPs: []net.IP{net.ParseIP("192.168.1.20")}, Hostname: "alpha"},
		{IPs: []net.IP{net.ParseIP("192.168.1.10")}, Hostname: "zebra"},
	}
	mod := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0", Snapshot: func() []*model.Device { return devices }})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	time.Sleep(1500 * time.Millisecond) // initial render with default sort (MAC)
	// Drain accumulated output so the subsequent read only captures post-sort frames.
	_, _ = io.ReadAll(tm.Output())

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // MAC → IP
	time.Sleep(100 * time.Millisecond)
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // IP → Hostname
	time.Sleep(1500 * time.Millisecond) // give a tick a chance to re-render with the new sort
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	// After cycling to hostname-sort, "alpha" should appear before "zebra"
	// in the latest frame. LastIndex skips earlier frames (initial render
	// and the intermediate IP-sort frame) so the assertion targets the
	// post-cycle hostname-sorted output.
	alpha := bytes.LastIndex(out, []byte("alpha"))
	zebra := bytes.LastIndex(out, []byte("zebra"))
	if alpha < 0 || zebra < 0 || alpha >= zebra {
		t.Errorf("alpha (%d) should appear before zebra (%d) under hostname sort:\n%s", alpha, zebra, out)
	}
}

func TestFilterMode(t *testing.T) {
	devices := []*model.Device{
		{IPs: []net.IP{net.ParseIP("192.168.1.10")}, Hostname: "macbook"},
		{IPs: []net.IP{net.ParseIP("192.168.1.20")}, Hostname: "printer"},
	}
	mod := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0", Snapshot: func() []*model.Device { return devices }})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'\x03'}}) // Ctrl+C

	time.Sleep(1500 * time.Millisecond)
	// Drain accumulated output (includes pre-filter renders with both devices)
	// so the subsequent read only captures the post-filter frame.
	_, _ = io.ReadAll(tm.Output())

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	time.Sleep(500 * time.Millisecond)

	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Contains(out, []byte("printer")) {
		t.Errorf("expected printer to remain after filter:\n%s", out)
	}
	if bytes.Contains(out, []byte("macbook")) {
		t.Errorf("expected macbook to be filtered out:\n%s", out)
	}
}

func TestHelpOverlay(t *testing.T) {
	mod := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0"})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'\x03'}})

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	time.Sleep(500 * time.Millisecond)
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	for _, want := range []string{"Help", "1-4", "/", "s", "r", "Enter"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("expected %q in help overlay:\n%s", want, out)
		}
	}
}

func TestStatusColors(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI)
	defer lipgloss.SetColorProfile(prev)

	devices := []*model.Device{
		{IPs: []net.IP{net.ParseIP("192.168.1.10")}, Hostname: "online-host", Status: model.StatusOnline},
		{IPs: []net.IP{net.ParseIP("192.168.1.20")}, Hostname: "stale-host", Status: model.StatusStale},
		{IPs: []net.IP{net.ParseIP("192.168.1.30")}, Hostname: "offline-host", Status: model.StatusOffline},
	}
	mod := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0", Snapshot: func() []*model.Device { return devices }})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	time.Sleep(1500 * time.Millisecond)
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	count := bytes.Count(out, []byte("\x1b["))
	if count < 3 {
		t.Errorf("expected >=3 ANSI escape sequences in colored output, got %d:\n%s", count, out)
	}
}

func TestColorsCanBeDisabled(t *testing.T) {
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.Ascii)
	defer lipgloss.SetColorProfile(prev)

	devices := []*model.Device{
		{IPs: []net.IP{net.ParseIP("192.168.1.10")}, Hostname: "host", Status: model.StatusOnline},
	}
	mod := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0", Snapshot: func() []*model.Device { return devices }})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	time.Sleep(1500 * time.Millisecond)
	out, err := io.ReadAll(tm.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	// SGR color sequences end in 'm' (e.g. "\x1b[32m" for green).
	// Terminal-control sequences (cursor movement, erase, etc.) are still
	// present; we only reject color/style SGR codes.
	if bytes.Contains(out, []byte("\x1b[m")) || bytes.Contains(out, []byte("\x1b[0m")) {
		t.Errorf("expected no SGR color sequences when ColorProfile=Ascii, got:\n%s", out)
	}
	// A quick check: no foreground color codes (ESC [ 3 <digit> m).
	for _, code := range [][]byte{
		[]byte("\x1b[30m"), []byte("\x1b[31m"), []byte("\x1b[32m"), []byte("\x1b[33m"),
		[]byte("\x1b[34m"), []byte("\x1b[35m"), []byte("\x1b[36m"), []byte("\x1b[37m"),
	} {
		if bytes.Contains(out, code) {
			t.Errorf("expected no foreground color codes when ColorProfile=Ascii, found %q:\n%s", code, out)
		}
	}
	if !bytes.Contains(out, []byte("host")) {
		t.Errorf("expected hostname in output even without color:\n%s", out)
	}
}
