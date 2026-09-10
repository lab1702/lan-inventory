// SPDX-License-Identifier: GPL-2.0-or-later

package snapshot_test

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/snapshot"
)

func sampleDevices() []*model.Device {
	return []*model.Device{
		{
			MAC:       "aa:bb:cc:dd:ee:01",
			IPs:       []net.IP{net.ParseIP("192.168.1.1")},
			Hostname:  "router",
			Vendor:    "TP-Link",
			OSGuess:   "Linux/macOS",
			Status:    model.StatusOnline,
			RTT:       1 * time.Millisecond,
			FirstSeen: time.Date(2026, 4, 25, 17, 0, 0, 0, time.UTC),
			LastSeen:  time.Date(2026, 4, 25, 17, 5, 0, 0, time.UTC),
			OpenPorts: []model.Port{{Number: 80, Proto: "tcp", Service: "http"}},
		},
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 4, 25, 17, 5, 0, 0, time.UTC)
	err := snapshot.WriteJSON(&buf, snapshot.Header{
		ScannedAt: now,
		Subnet:    "192.168.1.0/24",
		Iface:     "eth0",
	}, sampleDevices())
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var got struct {
		ScannedAt string         `json:"scanned_at"`
		Subnet    string         `json:"subnet"`
		Iface     string         `json:"interface"`
		Devices   []model.Device `json:"devices"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if got.Subnet != "192.168.1.0/24" {
		t.Errorf("subnet: %q", got.Subnet)
	}
	if got.Iface != "eth0" {
		t.Errorf("iface: %q", got.Iface)
	}
	if len(got.Devices) != 1 || got.Devices[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("devices: %+v", got.Devices)
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	err := snapshot.WriteTable(&buf, sampleDevices(), false)
	if err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"router", "192.168.1.1", "TP-Link"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("expected %q in table:\n%s", want, out)
		}
	}
}

func TestSnapshotsPreserveMeasuredZeroRTT(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rtt     time.Duration
		history []time.Duration
		want    string
		hasRTT  bool
	}{
		{"absent", 0, nil, "-", false},
		{"measured zero", 0, []time.Duration{0}, "0.0ms", true},
		{"positive without history", 1234 * time.Microsecond, nil, "1.2ms", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			devices := sampleDevices()
			devices[0].RTT, devices[0].RTTHistory = tc.rtt, tc.history
			var table bytes.Buffer
			if err := snapshot.WriteTable(&table, devices, false); err != nil {
				t.Fatalf("WriteTable: %v", err)
			}
			rows := strings.Split(strings.TrimSpace(table.String()), "\n")
			cells := strings.Fields(rows[2])
			if got := cells[len(cells)-2]; got != tc.want {
				t.Errorf("table RTT = %q, want %q", got, tc.want)
			}
			var encoded bytes.Buffer
			if err := snapshot.WriteJSON(&encoded, snapshot.Header{}, devices); err != nil {
				t.Fatalf("WriteJSON: %v", err)
			}
			var decoded struct {
				Devices []model.Device `json:"devices"`
			}
			if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil {
				t.Fatalf("decode JSON snapshot: %v", err)
			}
			if len(decoded.Devices) != 1 || decoded.Devices[0].HasRTT() != tc.hasRTT || decoded.Devices[0].RTT != tc.rtt {
				t.Fatalf("JSON snapshot lost RTT value or presence: %+v", decoded.Devices)
			}
		})
	}
}
