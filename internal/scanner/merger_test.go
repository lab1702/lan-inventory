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
	if events[0].Type != model.EventJoined {
		t.Errorf("first event (IP-only sighting) should be Joined, got %v", events[0].Type)
	}
	if events[1].Type != model.EventUpdated {
		t.Errorf("second event (MAC arrived for known IP) should be Updated, got %v", events[1].Type)
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

func TestMergerActiveAfterARPDoesNotDuplicate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan Update, 16)
	out := make(chan model.DeviceEvent, 16)
	m := NewMerger(MergerOptions{LeftAfter: time.Hour})
	go m.Run(ctx, in, out)

	// Step 1: ARP files the device under MAC.
	in <- Update{Source: "arp", Time: time.Now(), MAC: "aa:bb:cc:dd:ee:ff", IP: net.ParseIP("192.168.1.50")}
	// Step 2: Active prober pings the same IP — emits an Update with no MAC.
	in <- Update{Source: "active", Time: time.Now(), IP: net.ParseIP("192.168.1.50"), Alive: true, RTT: 1 * time.Millisecond}

	collectEvents(out, 2, 300*time.Millisecond)

	devices := m.Snapshot()
	if len(devices) != 1 {
		t.Errorf("expected 1 device after ARP+active for same IP, got %d", len(devices))
		for i, d := range devices {
			t.Logf("device[%d]: MAC=%q IPs=%v RTT=%v", i, d.MAC, d.IPs, d.RTT)
		}
		return
	}
	if devices[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC lost on merge: got %q, want aa:bb:cc:dd:ee:ff", devices[0].MAC)
	}
	if devices[0].RTT != 1*time.Millisecond {
		t.Errorf("RTT not merged from active update: got %v, want 1ms", devices[0].RTT)
	}
}

func TestMergerComputesOSDetect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan Update, 16)
	out := make(chan model.DeviceEvent, 16)
	m := NewMerger(MergerOptions{LeftAfter: time.Hour})
	go m.Run(ctx, in, out)

	// ARP brings vendor=Apple
	in <- Update{Source: "arp", Time: time.Now(), MAC: "aa:bb:cc:dd:ee:01", IP: net.ParseIP("192.168.1.10"), Vendor: "Apple"}
	// mDNS brings _airplay._tcp + TXT model=MacBookPro18,2
	in <- Update{Source: "mdns", Time: time.Now(), IP: net.ParseIP("192.168.1.10"), Services: []model.ServiceInst{
		{Type: "_airplay._tcp", Name: "mac1", Port: 7000, TXT: map[string]string{"model": "MacBookPro18,2"}},
	}}
	// Active brings TTL=128 (would normally be Windows by TTL alone)
	in <- Update{Source: "active", Time: time.Now(), IP: net.ParseIP("192.168.1.10"), Alive: true, TTL: 128, RTT: time.Millisecond}

	collectEvents(out, 3, 300*time.Millisecond)

	devices := m.Snapshot()
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].OSGuess != "macOS" {
		t.Errorf("OSGuess = %q, want macOS (TXT model should override TTL=128)", devices[0].OSGuess)
	}
}

func TestMergerKnownIPs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan Update, 16)
	out := make(chan model.DeviceEvent, 16)
	m := NewMerger(MergerOptions{LeftAfter: time.Hour})
	go m.Run(ctx, in, out)

	// ARP brings two devices — both are MAC-keyed and should appear in KnownIPs.
	in <- Update{Source: "arp", Time: time.Now(), MAC: "aa:bb:cc:dd:ee:01", IP: net.ParseIP("192.168.1.10")}
	in <- Update{Source: "arp", Time: time.Now(), MAC: "aa:bb:cc:dd:ee:02", IP: net.ParseIP("192.168.1.20")}
	// Active brings an IP-only entry — must NOT appear in KnownIPs (no ARP confirmation).
	in <- Update{Source: "active", Time: time.Now(), IP: net.ParseIP("192.168.1.30"), Alive: true}

	collectEvents(out, 3, 300*time.Millisecond)

	known := m.KnownIPs()
	if _, ok := known["192.168.1.10"]; !ok {
		t.Errorf("expected 192.168.1.10 in KnownIPs")
	}
	if _, ok := known["192.168.1.20"]; !ok {
		t.Errorf("expected 192.168.1.20 in KnownIPs")
	}
	if _, ok := known["192.168.1.30"]; ok {
		t.Errorf("did not expect 192.168.1.30 in KnownIPs (IP-only entry)")
	}
	if len(known) != 2 {
		t.Errorf("expected 2 known IPs, got %d: %v", len(known), known)
	}
}
