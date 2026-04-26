package tui_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

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
