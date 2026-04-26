package snapshot_test

import (
	"bytes"
	"encoding/json"
	"net"
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
		ScannedAt string          `json:"scanned_at"`
		Subnet    string          `json:"subnet"`
		Iface     string          `json:"interface"`
		Devices   []model.Device  `json:"devices"`
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
