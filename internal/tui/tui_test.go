package tui_test

import (
	"bytes"
	"io"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

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
