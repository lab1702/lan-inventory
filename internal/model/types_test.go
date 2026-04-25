package model_test

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

func TestDeviceJSONRoundTrip(t *testing.T) {
	original := model.Device{
		MAC:      "aa:bb:cc:dd:ee:ff",
		IPs:      []net.IP{net.ParseIP("192.168.1.10")},
		Hostname: "macbook.local",
		Vendor:   "Apple",
		OSGuess:  "macOS",
		OpenPorts: []model.Port{
			{Number: 22, Proto: "tcp", Service: "ssh"},
		},
		Services: []model.ServiceInst{
			{Type: "_ssh._tcp", Name: "macbook", Port: 22},
		},
		RTT:        2 * time.Millisecond,
		RTTHistory: []time.Duration{2 * time.Millisecond, 3 * time.Millisecond},
		FirstSeen:  time.Date(2026, 4, 25, 17, 0, 0, 0, time.UTC),
		LastSeen:   time.Date(2026, 4, 25, 17, 5, 0, 0, time.UTC),
		Status:     model.StatusOnline,
	}

	bytes, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got model.Device
	if err := json.Unmarshal(bytes, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.MAC != original.MAC {
		t.Errorf("MAC: got %q want %q", got.MAC, original.MAC)
	}
	if !got.FirstSeen.Equal(original.FirstSeen) {
		t.Errorf("FirstSeen: got %v want %v", got.FirstSeen, original.FirstSeen)
	}
	if got.Status != original.Status {
		t.Errorf("Status: got %v want %v", got.Status, original.Status)
	}
	if len(got.OpenPorts) != 1 || got.OpenPorts[0].Number != 22 {
		t.Errorf("OpenPorts not preserved: %v", got.OpenPorts)
	}
}

func TestStatusJSONString(t *testing.T) {
	cases := []struct {
		status model.Status
		want   string
	}{
		{model.StatusOnline, `"online"`},
		{model.StatusStale, `"stale"`},
		{model.StatusOffline, `"offline"`},
	}
	for _, c := range cases {
		bytes, err := json.Marshal(c.status)
		if err != nil {
			t.Fatalf("marshal %v: %v", c.status, err)
		}
		if string(bytes) != c.want {
			t.Errorf("%v: got %s want %s", c.status, bytes, c.want)
		}
	}
}
