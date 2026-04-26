// Package model holds the pure data types used across the scanner, snapshot
// writer, and TUI. No methods that perform I/O.
package model

import (
	"encoding/json"
	"net"
	"time"
)

type Device struct {
	MAC           string          `json:"mac"`
	IPs           []net.IP        `json:"ips"`
	Hostname      string          `json:"hostname"`
	Vendor        string          `json:"vendor"`
	OSGuess       string          `json:"os_guess"`
	OpenPorts     []Port          `json:"open_ports"`
	Services      []ServiceInst   `json:"services"`
	RTT           time.Duration   `json:"rtt_ns"`
	RTTHistory    []time.Duration `json:"rtt_history_ns"`
	FirstSeen     time.Time       `json:"first_seen"`
	LastSeen      time.Time       `json:"last_seen"`
	Status        Status          `json:"status"`
	TTL           int             `json:"ttl,omitempty"`
	NBNSResponded bool            `json:"nbns_responded,omitempty"`
}

type Port struct {
	Number  int    `json:"number"`
	Proto   string `json:"proto"`
	Service string `json:"service,omitempty"`
}

type ServiceInst struct {
	Type string            `json:"type"`
	Name string            `json:"name"`
	Port int               `json:"port"`
	TXT  map[string]string `json:"txt,omitempty"`
}

type Status int

const (
	StatusOnline Status = iota
	StatusStale
	StatusOffline
)

func (s Status) String() string {
	switch s {
	case StatusOnline:
		return "online"
	case StatusStale:
		return "stale"
	case StatusOffline:
		return "offline"
	default:
		return "unknown"
	}
}

func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Status) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	switch str {
	case "online":
		*s = StatusOnline
	case "stale":
		*s = StatusStale
	case "offline":
		*s = StatusOffline
	default:
		*s = StatusOffline
	}
	return nil
}

type EventType int

const (
	EventJoined EventType = iota
	EventUpdated
	EventLeft
)

func (e EventType) String() string {
	switch e {
	case EventJoined:
		return "joined"
	case EventUpdated:
		return "updated"
	case EventLeft:
		return "left"
	default:
		return "unknown"
	}
}

func (e EventType) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func (e *EventType) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	switch str {
	case "joined":
		*e = EventJoined
	case "updated":
		*e = EventUpdated
	case "left":
		*e = EventLeft
	default:
		*e = EventJoined
	}
	return nil
}

// Event is the user-facing record shown in the Events tab and stored in the
// in-session ring buffer.
type Event struct {
	Time time.Time `json:"time"`
	Type EventType `json:"type"`
	MAC  string    `json:"mac"`
	IP   net.IP    `json:"ip"`
	Note string    `json:"note,omitempty"`
}

// DeviceEvent is the internal channel message emitted by the scanner merger.
// It carries the full updated Device so consumers can diff or render without
// querying back into the merger.
type DeviceEvent struct {
	Type   EventType
	Device *Device
}
