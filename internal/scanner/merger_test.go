package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

func collectEvents(ch <-chan model.DeviceEvent, want int, timeout time.Duration) []model.DeviceEvent {
	var got []model.DeviceEvent
	deadline := time.After(timeout)
	for len(got) < want {
		select {
		case e, ok := <-ch:
			if !ok {
				return got
			}
			got = append(got, e)
		case <-deadline:
			return got
		}
	}
	return got
}

func TestMergerJoinedOnNewMAC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan Update, 16)
	out := make(chan model.DeviceEvent, 16)
	m := NewMerger(MergerOptions{LeftAfter: time.Hour}) // disable Left during this test
	go m.Run(ctx, in, out)

	in <- Update{Source: "arp", Time: time.Now(), MAC: "aa:bb:cc:dd:ee:01", IP: net.ParseIP("192.168.1.10")}

	events := collectEvents(out, 1, 200*time.Millisecond)
	if len(events) != 1 || events[0].Type != model.EventJoined {
		t.Fatalf("expected 1 Joined, got %v", events)
	}
	if events[0].Device.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MAC mismatch: %v", events[0].Device)
	}
}

func TestMergerUpdatedNotJoinedOnSecondSighting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan Update, 16)
	out := make(chan model.DeviceEvent, 16)
	m := NewMerger(MergerOptions{LeftAfter: time.Hour})
	go m.Run(ctx, in, out)

	in <- Update{Source: "arp", Time: time.Now(), MAC: "aa:bb:cc:dd:ee:01", IP: net.ParseIP("192.168.1.10")}
	in <- Update{Source: "mdns", Time: time.Now(), MAC: "aa:bb:cc:dd:ee:01", IP: net.ParseIP("192.168.1.10"), Hostname: "host.local"}

	events := collectEvents(out, 2, 300*time.Millisecond)
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d: %v", len(events), events)
	}
	if events[0].Type != model.EventJoined {
		t.Errorf("first should be Joined, got %v", events[0].Type)
	}
	if events[1].Type != model.EventUpdated {
		t.Errorf("second should be Updated, got %v", events[1].Type)
	}
	if events[1].Device.Hostname != "host.local" {
		t.Errorf("hostname not merged: %v", events[1].Device)
	}
}

func TestMergerIPOnlyThenMACMerges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan Update, 16)
	out := make(chan model.DeviceEvent, 16)
	m := NewMerger(MergerOptions{LeftAfter: time.Hour})
	go m.Run(ctx, in, out)

	// First sighting: active prober found host alive, no MAC yet
	in <- Update{Source: "active", Time: time.Now(), IP: net.ParseIP("192.168.1.50"), Alive: true, RTT: 1 * time.Millisecond}
	// Second sighting: ARP brings the MAC
	in <- Update{Source: "arp", Time: time.Now(), MAC: "aa:bb:cc:dd:ee:02", IP: net.ParseIP("192.168.1.50")}

	events := collectEvents(out, 2, 300*time.Millisecond)
	if len(events) < 2 {
		t.Fatalf("expected at least 2 events, got %d", len(events))
	}
	last := events[len(events)-1]
	if last.Device.MAC != "aa:bb:cc:dd:ee:02" {
		t.Errorf("MAC should be merged, got %q", last.Device.MAC)
	}
	if last.Device.RTT != 1*time.Millisecond {
		t.Errorf("RTT should be preserved across merge, got %v", last.Device.RTT)
	}
}

func TestMergerLeftAfterTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan Update, 16)
	out := make(chan model.DeviceEvent, 16)
	m := NewMerger(MergerOptions{StaleAfter: 40 * time.Millisecond, LeftAfter: 100 * time.Millisecond, SweepInterval: 25 * time.Millisecond})
	go m.Run(ctx, in, out)

	in <- Update{Source: "arp", Time: time.Now(), MAC: "aa:bb:cc:dd:ee:03", IP: net.ParseIP("192.168.1.60")}

	// Drain Joined first
	collectEvents(out, 1, 200*time.Millisecond)

	// Wait for Left
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case e := <-out:
			if e.Type == model.EventLeft {
				return
			}
		case <-deadline:
			t.Fatalf("did not see Left event in time")
		}
	}
}
