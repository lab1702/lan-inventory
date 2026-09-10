// SPDX-License-Identifier: GPL-2.0-or-later

package tui

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/lab1702/lan-inventory/internal/model"
)

func TestCurrentRTTDistinguishesMeasuredZeroFromAbsent(t *testing.T) {
	profile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.Ascii)
	defer lipgloss.SetColorProfile(profile)
	for _, tc := range []struct {
		name    string
		rtt     time.Duration
		history []time.Duration
		want    string
	}{
		{"absent", 0, nil, "-"},
		{"measured zero", 0, []time.Duration{0}, "0.0ms"},
		{"positive without history", 1234 * time.Microsecond, nil, "1.2ms"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(Deps{})
			m.devices = []*model.Device{{
				MAC: "02:00:00:00:00:01", IPs: []net.IP{net.ParseIP("192.168.1.1")},
				RTT: tc.rtt, RTTHistory: tc.history,
			}}
			rows := contentLines(m.viewDevices())
			if !strings.HasSuffix(strings.TrimSpace(rows[0]), "RTT") {
				t.Fatal("expected RTT to be the final table column at the default width")
			}
			cells := strings.Fields(rows[2])
			if got := cells[len(cells)-1]; got != tc.want {
				t.Errorf("table RTT = %q, want %q", got, tc.want)
			}
			detail := strings.TrimSpace(m.deviceDetailLines()[3])
			if want := "RTT: " + tc.want; detail != want {
				t.Errorf("detail RTT = %q, want %q", detail, want)
			}
		})
	}
}

func TestRTTHistoryKeepsZeroSamplesVisible(t *testing.T) {
	profile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.Ascii)
	defer lipgloss.SetColorProfile(profile)
	d := &model.Device{RTTHistory: []time.Duration{0, 1234 * time.Microsecond, 0}}
	if got := detailStrip(d); !strings.Contains(got, "RTT history: 0.0ms 1.2ms 0.0ms") {
		t.Fatalf("measured history zero must not become an absent marker:\n%s", got)
	}
}
