# lan-inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-binary Go tool that auto-discovers home-LAN devices, presents a 4-tab Bubble Tea TUI dashboard, and supports a `--once` non-interactive mode that prints JSON or a text table.

**Architecture:** All-in-one Go process. Scanner runs three concurrent workers (passive ARP via libpcap, passive mDNS via zeroconf, active prober calling stdlib + pro-bing). All updates funnel into a single merger goroutine that owns a `map[mac]*Device` and emits `DeviceEvent`s on a channel. The TUI consumes events; `--once` consumes one cycle and exits. State is in-memory only.

**Tech Stack:**
- Go 1.22+
- TUI: `github.com/charmbracelet/bubbletea`, `github.com/charmbracelet/lipgloss`
- ARP sniffing: `github.com/google/gopacket` + libpcap
- mDNS: `github.com/grandcat/zeroconf`
- ICMP ping: `github.com/prometheus-community/pro-bing`
- TUI testing: `github.com/charmbracelet/x/exp/teatest`
- Static analysis: `staticcheck` from `honnef.co/go/tools`

**Spec:** `docs/superpowers/specs/2026-04-25-lan-inventory-design.md`

---

## File structure

```
.
├── Makefile
├── README.md
├── go.mod
├── go.sum
├── .github/workflows/ci.yml
├── cmd/lan-inventory/
│   └── main.go
└── internal/
    ├── model/
    │   ├── types.go
    │   └── types_test.go
    ├── oui/
    │   ├── oui.go
    │   ├── oui_test.go
    │   └── manuf.txt              (embedded vendor data)
    ├── netiface/
    │   ├── netiface.go
    │   └── netiface_test.go
    ├── probe/
    │   ├── osguess.go
    │   ├── osguess_test.go
    │   ├── ping.go
    │   ├── ping_test.go
    │   ├── ports.go
    │   ├── ports_test.go
    │   ├── dns.go
    │   └── dns_test.go
    ├── scanner/
    │   ├── interfaces.go         (Worker interfaces; tests inject fakes)
    │   ├── merger.go
    │   ├── merger_test.go
    │   ├── arp.go                 (gopacket-based ARP worker)
    │   ├── mdns.go                (zeroconf-based mDNS worker)
    │   ├── active.go              (active prober worker)
    │   └── scanner.go             (top-level Scanner type wiring it all)
    ├── snapshot/
    │   ├── snapshot.go
    │   └── snapshot_test.go
    └── tui/
        ├── model.go               (root Bubble Tea model + tab switching)
        ├── devices.go             (Devices tab)
        ├── services.go            (Services tab)
        ├── subnet.go              (Subnet tab)
        ├── events.go              (Events tab)
        ├── tui_test.go
        └── testdata/              (.golden files)
```

---

## Task 1: Project scaffolding

**Files:**
- Create: `go.mod`
- Create: `Makefile`
- Create: `.github/workflows/ci.yml`
- Create: `cmd/lan-inventory/main.go`
- Create: `README.md`

- [ ] **Step 1.1: Initialize Go module**

```bash
cd /home/lab/tmp/lan-inventory
go mod init github.com/lab1702/lan-inventory
```

Expected: creates `go.mod` with `module github.com/lab1702/lan-inventory` and `go 1.22`.

- [ ] **Step 1.2: Create minimal main.go that compiles and prints version**

`cmd/lan-inventory/main.go`:

```go
package main

import "fmt"

const version = "0.1.0-dev"

func main() {
	fmt.Printf("lan-inventory %s\n", version)
}
```

- [ ] **Step 1.3: Verify build**

```bash
go build ./...
./lan-inventory
```

Expected: prints `lan-inventory 0.1.0-dev`. Then delete the produced binary: `rm -f lan-inventory`.

- [ ] **Step 1.4: Create Makefile**

`Makefile`:

```make
.PHONY: build test lint vet smoke clean

build:
	go build -o bin/lan-inventory ./cmd/lan-inventory

test:
	go test ./...

vet:
	go vet ./...

lint:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

smoke: build
	sudo setcap cap_net_raw,cap_net_admin=eip ./bin/lan-inventory
	./bin/lan-inventory --once --table

clean:
	rm -rf bin/
```

- [ ] **Step 1.5: Create CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [master, main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Install libpcap
        run: sudo apt-get update && sudo apt-get install -y libpcap-dev
      - run: go vet ./...
      - run: go run honnef.co/go/tools/cmd/staticcheck@latest ./...
      - run: go test ./...
```

- [ ] **Step 1.6: Create minimal README**

`README.md`:

```markdown
# lan-inventory

A zero-config home-LAN inventory tool. Run it, see your network.

## Install

```bash
go install github.com/lab1702/lan-inventory/cmd/lan-inventory@latest
sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-inventory)
```

Or build from source:

```bash
make build
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/lan-inventory
./bin/lan-inventory
```

## Usage

```bash
lan-inventory               # interactive TUI dashboard
lan-inventory --once        # one scan, print JSON, exit
lan-inventory --once --table # one scan, print table, exit
lan-inventory --version
lan-inventory --help
```

See `docs/superpowers/specs/` for the design.
```

- [ ] **Step 1.7: Commit**

```bash
git add go.mod cmd/ Makefile .github/ README.md
git commit -m "scaffold: Go module, Makefile, CI, minimal main"
```

---

## Task 2: model package

**Files:**
- Create: `internal/model/types.go`
- Create: `internal/model/types_test.go`

- [ ] **Step 2.1: Write failing JSON round-trip test**

`internal/model/types_test.go`:

```go
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
```

- [ ] **Step 2.2: Run test to verify it fails**

```bash
go test ./internal/model/ -v
```

Expected: FAIL — package `model` does not exist.

- [ ] **Step 2.3: Implement types.go**

`internal/model/types.go`:

```go
// Package model holds the pure data types used across the scanner, snapshot
// writer, and TUI. No methods that perform I/O.
package model

import (
	"encoding/json"
	"net"
	"time"
)

type Device struct {
	MAC        string          `json:"mac"`
	IPs        []net.IP        `json:"ips"`
	Hostname   string          `json:"hostname"`
	Vendor     string          `json:"vendor"`
	OSGuess    string          `json:"os_guess"`
	OpenPorts  []Port          `json:"open_ports"`
	Services   []ServiceInst   `json:"services"`
	RTT        time.Duration   `json:"rtt_ns"`
	RTTHistory []time.Duration `json:"rtt_history_ns"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	Status     Status          `json:"status"`
}

type Port struct {
	Number  int    `json:"number"`
	Proto   string `json:"proto"`
	Service string `json:"service,omitempty"`
}

type ServiceInst struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Port int    `json:"port"`
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
```

- [ ] **Step 2.4: Run tests to verify they pass**

```bash
go test ./internal/model/ -v
```

Expected: PASS for both `TestDeviceJSONRoundTrip` and `TestStatusJSONString`.

- [ ] **Step 2.5: Commit**

```bash
git add internal/model/
git commit -m "model: Device/Port/ServiceInst/Event/DeviceEvent types with JSON round-trip"
```

---

## Task 3: oui package

**Files:**
- Create: `internal/oui/manuf.txt`
- Create: `internal/oui/oui.go`
- Create: `internal/oui/oui_test.go`

- [ ] **Step 3.1: Create starter manuf.txt with a few well-known prefixes**

`internal/oui/manuf.txt`:

```
# Trimmed Wireshark manuf format: OUI <tab> short <tab> long
# A full database can be substituted later; format is `XX:XX:XX\t<short>\t<long>`.
00:1B:63	Apple	Apple, Inc.
3C:22:FB	Apple	Apple, Inc.
B8:27:EB	RaspberryPi	Raspberry Pi Foundation
DC:A6:32	RaspberryPi	Raspberry Pi Foundation
D8:0F:99	TP-Link	TP-LINK TECHNOLOGIES CO.,LTD.
A4:C3:F0	Sonos	Sonos, Inc.
FC:FF:AA	HP	Hewlett Packard
74:C2:46	Espressif	Espressif Inc.
18:B4:30	NestLabs	Nest Labs Inc.
90:48:9A	Tuya	Tuya Smart Inc.
```

(A larger file can be substituted by downloading https://www.wireshark.org/download/automated/data/manuf and saving here. The format is identical.)

- [ ] **Step 3.2: Write failing tests**

`internal/oui/oui_test.go`:

```go
package oui_test

import (
	"testing"

	"github.com/lab1702/lan-inventory/internal/oui"
)

func TestLookupKnown(t *testing.T) {
	cases := []struct {
		mac  string
		want string
	}{
		{"00:1b:63:aa:bb:cc", "Apple"},
		{"00:1B:63:AA:BB:CC", "Apple"},
		{"b8:27:eb:11:22:33", "RaspberryPi"},
		{"d8:0f:99:99:99:99", "TP-Link"},
	}
	for _, c := range cases {
		got := oui.Lookup(c.mac)
		if got != c.want {
			t.Errorf("Lookup(%q) = %q, want %q", c.mac, got, c.want)
		}
	}
}

func TestLookupUnknown(t *testing.T) {
	cases := []string{
		"",
		"not-a-mac",
		"ff:ff:ff:ff:ff:ff",
		"01:02:03:04:05:06",
	}
	for _, c := range cases {
		if got := oui.Lookup(c); got != "" {
			t.Errorf("Lookup(%q) = %q, want empty", c, got)
		}
	}
}
```

- [ ] **Step 3.3: Run tests to verify they fail**

```bash
go test ./internal/oui/ -v
```

Expected: FAIL — package does not exist.

- [ ] **Step 3.4: Implement oui.go**

`internal/oui/oui.go`:

```go
// Package oui resolves a MAC address to a vendor short-name using an
// embedded copy of Wireshark's manuf database (or a trimmed equivalent).
package oui

import (
	"bufio"
	_ "embed"
	"strings"
	"sync"
)

//go:embed manuf.txt
var manufRaw string

var (
	once  sync.Once
	table map[string]string
)

func loadTable() {
	table = make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(manufRaw))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			continue
		}
		prefix := strings.ToUpper(strings.TrimSpace(parts[0]))
		short := strings.TrimSpace(parts[1])
		if prefix == "" || short == "" {
			continue
		}
		table[prefix] = short
	}
}

// Lookup returns the vendor short-name for the given MAC, or "" if unknown.
// Accepts uppercase or lowercase, with colon separators.
func Lookup(mac string) string {
	once.Do(loadTable)
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToUpper(mac[:8])
	if !strings.Contains(prefix, ":") {
		return ""
	}
	return table[prefix]
}
```

- [ ] **Step 3.5: Run tests to verify they pass**

```bash
go test ./internal/oui/ -v
```

Expected: PASS for both tests.

- [ ] **Step 3.6: Commit**

```bash
git add internal/oui/
git commit -m "oui: embedded MAC-vendor lookup with manuf format"
```

---

## Task 4: netiface package

**Files:**
- Create: `internal/netiface/netiface.go`
- Create: `internal/netiface/netiface_test.go`

The default-route detection is hard to unit-test (depends on host routing table). We test the *subnet-size guard* — a pure function — and treat default-route detection as integration code covered by manual smoke tests.

- [ ] **Step 4.1: Write failing tests for the subnet-size guard**

`internal/netiface/netiface_test.go`:

```go
package netiface_test

import (
	"net"
	"testing"

	"github.com/lab1702/lan-inventory/internal/netiface"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestCheckSubnetSize(t *testing.T) {
	cases := []struct {
		name    string
		subnet  *net.IPNet
		wantErr bool
	}{
		{"slash 24 ok", mustCIDR("192.168.1.0/24"), false},
		{"slash 25 ok", mustCIDR("192.168.1.0/25"), false},
		{"slash 22 ok (boundary)", mustCIDR("10.0.0.0/22"), false},
		{"slash 21 too big", mustCIDR("10.0.0.0/21"), true},
		{"slash 16 too big", mustCIDR("10.0.0.0/16"), true},
		{"slash 8 too big", mustCIDR("10.0.0.0/8"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := netiface.CheckSubnetSize(c.subnet)
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestSubnetIPs(t *testing.T) {
	subnet := mustCIDR("192.168.1.0/30") // .0, .1, .2, .3 — middle two usable
	ips := netiface.SubnetIPs(subnet)
	got := []string{}
	for _, ip := range ips {
		got = append(got, ip.String())
	}
	want := []string{"192.168.1.1", "192.168.1.2"}
	if len(got) != len(want) {
		t.Fatalf("got %d ips %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("ip[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}
```

- [ ] **Step 4.2: Run tests to verify they fail**

```bash
go test ./internal/netiface/ -v
```

Expected: FAIL — package does not exist.

- [ ] **Step 4.3: Implement netiface.go**

`internal/netiface/netiface.go`:

```go
// Package netiface auto-detects the default network interface and its IPv4
// subnet, and provides helpers for iterating the subnet.
package netiface

import (
	"errors"
	"fmt"
	"net"
)

// Info describes the interface chosen for scanning.
type Info struct {
	Name   string
	Subnet *net.IPNet
	HostIP net.IP // our own IP on this interface
}

// MaxPrefixOnesAllowed is the maximum prefix length that's "small enough" — a
// /22 and below is permitted. Anything larger (e.g., /20, /16) is refused.
const MinPrefixOnesAllowed = 22 // ones >= 22 ⇒ subnet ≤ /22

// ErrSubnetTooLarge is returned by CheckSubnetSize when the subnet is bigger
// than the design ceiling.
var ErrSubnetTooLarge = errors.New("subnet too large")

// CheckSubnetSize validates that the subnet's size is within design limits.
// Returns nil for /22 and smaller (more host bits = smaller; ones >= 22).
func CheckSubnetSize(subnet *net.IPNet) error {
	ones, bits := subnet.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("not an IPv4 subnet: %s", subnet)
	}
	if ones < MinPrefixOnesAllowed {
		return fmt.Errorf("%w: subnet /%d too large — this tool targets home-LAN /24 deployments", ErrSubnetTooLarge, ones)
	}
	return nil
}

// SubnetIPs returns all usable host IPs in the subnet (excludes network and
// broadcast addresses for IPv4).
func SubnetIPs(subnet *net.IPNet) []net.IP {
	var out []net.IP
	ip := subnet.IP.Mask(subnet.Mask).To4()
	if ip == nil {
		return out
	}
	for cur := make(net.IP, 4); ; {
		copy(cur, ip)
		if !subnet.Contains(cur) {
			break
		}
		// skip network and broadcast
		ones, _ := subnet.Mask.Size()
		isNetwork := equalIP(cur, subnet.IP.Mask(subnet.Mask))
		isBroadcast := isBroadcastAddr(cur, subnet)
		if !isNetwork && !isBroadcast || ones == 32 || ones == 31 {
			out = append(out, append(net.IP{}, cur...))
		}
		// increment
		incIP(ip)
		if !subnet.Contains(ip) {
			break
		}
	}
	return out
}

func equalIP(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if a4[i] != b4[i] {
			return false
		}
	}
	return true
}

func isBroadcastAddr(ip net.IP, subnet *net.IPNet) bool {
	mask := subnet.Mask
	bcast := make(net.IP, 4)
	base := subnet.IP.To4()
	for i := 0; i < 4; i++ {
		bcast[i] = base[i] | ^mask[i]
	}
	return equalIP(ip, bcast)
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

// Detect picks the interface owning the default IPv4 route, validates the
// subnet size, and returns Info. This function reads OS state and is not
// unit-tested; covered by manual smoke testing.
func Detect() (*Info, error) {
	defaultIface, err := defaultRouteInterface()
	if err != nil {
		return nil, err
	}
	addrs, err := defaultIface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("read addrs for %s: %w", defaultIface.Name, err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		// Build subnet from mask
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			continue
		}
		subnet := &net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: net.CIDRMask(ones, 32)}
		if err := CheckSubnetSize(subnet); err != nil {
			return nil, err
		}
		return &Info{Name: defaultIface.Name, Subnet: subnet, HostIP: ip4}, nil
	}
	return nil, fmt.Errorf("no IPv4 address on interface %s", defaultIface.Name)
}
```

- [ ] **Step 4.4: Add platform-specific default-route lookup (Linux first)**

`internal/netiface/route_linux.go`:

```go
//go:build linux

package netiface

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// defaultRouteInterface reads /proc/net/route and returns the interface that
// owns the default route (destination 00000000 with the lowest metric).
func defaultRouteInterface() (*net.Interface, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/route: %w", err)
	}
	defer f.Close()

	type cand struct {
		iface  string
		metric int
	}
	var best *cand

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		// Default route has destination 00000000 and mask 00000000
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		var metric int
		fmt.Sscanf(fields[6], "%d", &metric)
		if best == nil || metric < best.metric {
			best = &cand{iface: fields[0], metric: metric}
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no default route — cannot determine which subnet to scan")
	}
	iface, err := net.InterfaceByName(best.iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", best.iface, err)
	}
	return iface, nil
}
```

`internal/netiface/route_other.go`:

```go
//go:build !linux

package netiface

import (
	"fmt"
	"net"
)

func defaultRouteInterface() (*net.Interface, error) {
	return nil, fmt.Errorf("default route detection not implemented on this platform")
}
```

- [ ] **Step 4.5: Run tests to verify they pass**

```bash
go test ./internal/netiface/ -v
```

Expected: PASS for `TestCheckSubnetSize` and `TestSubnetIPs`.

- [ ] **Step 4.6: Commit**

```bash
git add internal/netiface/
git commit -m "netiface: subnet-size guard, IPv4 host enumeration, Linux default-route detection"
```

---

## Task 5: probe.OSGuess

**Files:**
- Create: `internal/probe/osguess.go`
- Create: `internal/probe/osguess_test.go`

- [ ] **Step 5.1: Write failing tests**

`internal/probe/osguess_test.go`:

```go
package probe_test

import (
	"testing"

	"github.com/lab1702/lan-inventory/internal/probe"
)

func TestOSGuess(t *testing.T) {
	cases := []struct {
		ttl  int
		want string
	}{
		{0, ""},
		{32, "Windows"},          // older Windows / some embedded
		{64, "Linux/macOS"},      // typical Unix
		{128, "Windows"},          // modern Windows
		{255, "RTOS/Network"},    // routers, embedded RTOS
		{63, "Linux/macOS"},      // 1 hop away from 64
		{60, "Linux/macOS"},
		{127, "Windows"},
		{254, "RTOS/Network"},
		{248, "RTOS/Network"},    // 7 hops below 255 — within tolerance
		{200, ""},                 // 55 hops below 255 — outside tolerance
		{1, ""},                   // nonsense
	}
	for _, c := range cases {
		got := probe.OSGuess(c.ttl)
		if got != c.want {
			t.Errorf("OSGuess(%d) = %q, want %q", c.ttl, got, c.want)
		}
	}
}
```

- [ ] **Step 5.2: Run test to verify it fails**

```bash
go test ./internal/probe/ -v -run TestOSGuess
```

Expected: FAIL — function does not exist.

- [ ] **Step 5.3: Implement osguess.go**

`internal/probe/osguess.go`:

```go
// Package probe contains stateless probing functions: ping, port scan, OS
// guess by TTL, and reverse DNS lookup.
package probe

// OSGuess returns a coarse OS family guess from an observed ICMP TTL value.
// Hosts decrement TTL by 1 per hop, so observed TTL is initial-TTL minus
// (hops - 1). On a home LAN, hops are typically 0–2.
//
//   - 32  → older Windows / some embedded
//   - 64  → Linux / macOS / *BSD / Android
//   - 128 → modern Windows
//   - 255 → routers, RTOS, network gear
//
// Returns "" for TTLs that don't plausibly correspond to any of these
// initial values (within a tolerance of 8 hops).
func OSGuess(ttl int) string {
	if ttl <= 0 {
		return ""
	}
	type bucket struct {
		initial int
		label   string
	}
	buckets := []bucket{
		{32, "Windows"},
		{64, "Linux/macOS"},
		{128, "Windows"},
		{255, "RTOS/Network"},
	}
	const tolerance = 8 // up to ~8 hops difference
	bestDelta := tolerance + 1
	best := ""
	for _, b := range buckets {
		if ttl > b.initial {
			continue
		}
		delta := b.initial - ttl
		if delta < bestDelta {
			bestDelta = delta
			best = b.label
		}
	}
	return best
}
```

- [ ] **Step 5.4: Run test to verify it passes**

```bash
go test ./internal/probe/ -v -run TestOSGuess
```

Expected: PASS.

- [ ] **Step 5.5: Commit**

```bash
git add internal/probe/
git commit -m "probe: OSGuess by TTL with hop tolerance"
```

---

## Task 6: probe.Ping

**Files:**
- Create: `internal/probe/ping.go`
- Create: `internal/probe/ping_test.go`

- [ ] **Step 6.1: Add pro-bing dependency**

```bash
go get github.com/prometheus-community/pro-bing
```

- [ ] **Step 6.2: Write failing test (uses 127.0.0.1; no raw socket if "udp" mode is used)**

`internal/probe/ping_test.go`:

```go
package probe_test

import (
	"context"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/probe"
)

func TestPingLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := probe.Ping(ctx, "127.0.0.1")
	if err != nil {
		t.Skipf("Ping failed (raw socket unavailable in test env): %v", err)
	}
	if !res.Alive {
		t.Errorf("expected localhost alive")
	}
	if res.RTT <= 0 {
		t.Errorf("expected positive RTT, got %v", res.RTT)
	}
	if res.TTL <= 0 {
		t.Errorf("expected positive TTL, got %d", res.TTL)
	}
}

func TestPingDeadIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use a documentation-reserved address (RFC 5737) that should not respond.
	res, err := probe.Ping(ctx, "192.0.2.1")
	if err != nil {
		t.Skipf("Ping setup failed (raw socket unavailable): %v", err)
	}
	if res.Alive {
		t.Errorf("expected 192.0.2.1 not alive, got %v", res)
	}
}
```

- [ ] **Step 6.3: Run test to verify it fails**

```bash
go test ./internal/probe/ -v -run TestPing
```

Expected: FAIL — function does not exist.

- [ ] **Step 6.4: Implement ping.go**

`internal/probe/ping.go`:

```go
package probe

import (
	"context"
	"fmt"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// PingResult is the outcome of a single ICMP ping attempt.
type PingResult struct {
	Alive bool
	RTT   time.Duration
	TTL   int
}

// Ping sends a single ICMP echo to the given IP and waits for a reply, with
// the timeout taken from ctx. Requires raw socket privilege; the caller is
// responsible for surfacing setup errors.
func Ping(ctx context.Context, ip string) (PingResult, error) {
	pinger, err := probing.NewPinger(ip)
	if err != nil {
		return PingResult{}, fmt.Errorf("new pinger: %w", err)
	}
	pinger.SetPrivileged(true)
	pinger.Count = 1
	pinger.Timeout = 1 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < pinger.Timeout {
			pinger.Timeout = rem
		}
	}

	var ttl int
	pinger.OnRecv = func(pkt *probing.Packet) { ttl = pkt.TTL }

	if err := pinger.RunWithContext(ctx); err != nil {
		return PingResult{}, fmt.Errorf("ping: %w", err)
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return PingResult{Alive: false}, nil
	}
	return PingResult{
		Alive: true,
		RTT:   stats.AvgRtt,
		TTL:   ttl,
	}, nil
}
```

- [ ] **Step 6.5: Run test to verify it passes (or skips with a clear reason)**

```bash
go test ./internal/probe/ -v -run TestPing
```

Expected: PASS if running with privilege, or SKIP if raw socket unavailable.

- [ ] **Step 6.6: Commit**

```bash
git add internal/probe/ping.go internal/probe/ping_test.go go.mod go.sum
git commit -m "probe: ICMP ping with context-aware timeout"
```

---

## Task 7: probe.ScanPorts

**Files:**
- Create: `internal/probe/ports.go`
- Create: `internal/probe/ports_test.go`

- [ ] **Step 7.1: Write failing test using a localhost listener fixture**

`internal/probe/ports_test.go`:

```go
package probe_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/probe"
)

func startListener(t *testing.T) (host string, port int, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return "127.0.0.1", addr.Port, func() { l.Close() }
}

func TestScanPortsOpenAndClosed(t *testing.T) {
	host, port, stop := startListener(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Closed port: pick the listener's port + 1 (very likely closed).
	closedPort := port + 1
	results := probe.ScanPorts(ctx, host, []int{port, closedPort}, 200*time.Millisecond)

	if len(results) != 1 {
		t.Fatalf("expected 1 open port, got %d (%v)", len(results), results)
	}
	if results[0].Number != port || results[0].Proto != "tcp" {
		t.Errorf("got %+v, want port %d/tcp", results[0], port)
	}
}

func TestScanPortsRespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := probe.ScanPorts(ctx, "127.0.0.1", []int{1, 2, 3}, 100*time.Millisecond)
	if len(results) != 0 {
		t.Errorf("expected no results on cancelled ctx, got %v", results)
	}
}

func TestServiceLabel(t *testing.T) {
	cases := map[int]string{22: "ssh", 53: "dns", 80: "http", 443: "https", 9999: ""}
	for n, want := range cases {
		got := probe.ServiceLabel(n)
		if got != want {
			t.Errorf("ServiceLabel(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestDefaultPorts(t *testing.T) {
	if len(probe.DefaultPorts()) < 10 {
		t.Errorf("DefaultPorts seems too short: %v", probe.DefaultPorts())
	}
	// must be sorted ascending and unique
	prev := -1
	for _, p := range probe.DefaultPorts() {
		if p <= prev {
			t.Errorf("ports not sorted ascending unique: %v", probe.DefaultPorts())
			break
		}
		prev = p
	}
	_ = strconv.Itoa(0) // silence unused import if test pruned later
}
```

- [ ] **Step 7.2: Run test to verify it fails**

```bash
go test ./internal/probe/ -v -run TestScanPorts
```

Expected: FAIL — function does not exist.

- [ ] **Step 7.3: Implement ports.go**

`internal/probe/ports.go`:

```go
package probe

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

// DefaultPorts is the fixed shortlist scanned by the active prober.
func DefaultPorts() []int {
	return []int{22, 53, 80, 443, 445, 631, 1400, 5000, 5353, 8080, 9100}
}

// ScanPorts attempts a TCP connect to each port on host with the given
// per-port timeout, in parallel. Returns only the ports that accepted the
// connection. Respects ctx cancellation.
func ScanPorts(ctx context.Context, host string, ports []int, perPortTimeout time.Duration) []model.Port {
	if ctx.Err() != nil {
		return nil
	}
	var (
		mu     sync.Mutex
		out    []model.Port
		wg     sync.WaitGroup
		dialer = net.Dialer{Timeout: perPortTimeout}
	)
	for _, p := range ports {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			cctx, cancel := context.WithTimeout(ctx, perPortTimeout)
			defer cancel()
			conn, err := dialer.DialContext(cctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p)))
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			out = append(out, model.Port{Number: p, Proto: "tcp", Service: ServiceLabel(p)})
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out
}

// ServiceLabel returns the conventional name for a well-known port, or "".
func ServiceLabel(port int) string {
	switch port {
	case 22:
		return "ssh"
	case 53:
		return "dns"
	case 80, 8080:
		return "http"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 631:
		return "ipp"
	case 1400:
		return "sonos"
	case 5000:
		return "upnp"
	case 5353:
		return "mdns"
	case 9100:
		return "jetdirect"
	}
	return ""
}
```

- [ ] **Step 7.4: Run tests to verify they pass**

```bash
go test ./internal/probe/ -v
```

Expected: PASS for all probe tests so far.

- [ ] **Step 7.5: Commit**

```bash
git add internal/probe/ports.go internal/probe/ports_test.go
git commit -m "probe: ScanPorts with worker-pool TCP-connect, ServiceLabel for well-known ports"
```

---

## Task 8: probe.ReverseDNS

**Files:**
- Create: `internal/probe/dns.go`
- Create: `internal/probe/dns_test.go`

- [ ] **Step 8.1: Write failing test**

`internal/probe/dns_test.go`:

```go
package probe_test

import (
	"context"
	"testing"
	"time"

	"github.com/lab1702/lan-inventory/internal/probe"
)

func TestReverseDNSLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	got := probe.ReverseDNS(ctx, "127.0.0.1")
	// localhost resolution may or may not return "localhost." — we only
	// require that it does not panic and either returns "" or a non-empty
	// string ending with "." (FQDN canonicalization handled internally).
	if got != "" && got != "localhost" {
		t.Logf("ReverseDNS(127.0.0.1) = %q (informational)", got)
	}
}

func TestReverseDNSUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 192.0.2.0/24 (TEST-NET-1) should not resolve.
	got := probe.ReverseDNS(ctx, "192.0.2.123")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}
```

- [ ] **Step 8.2: Run test to verify it fails**

```bash
go test ./internal/probe/ -v -run TestReverseDNS
```

Expected: FAIL — function does not exist.

- [ ] **Step 8.3: Implement dns.go**

`internal/probe/dns.go`:

```go
package probe

import (
	"context"
	"net"
	"strings"
)

// ReverseDNS does a PTR lookup for ip and returns the first result, with the
// trailing dot trimmed. Returns "" on timeout, no result, or any error.
func ReverseDNS(ctx context.Context, ip string) string {
	resolver := net.DefaultResolver
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
```

- [ ] **Step 8.4: Run tests to verify they pass**

```bash
go test ./internal/probe/ -v
```

Expected: all probe tests PASS.

- [ ] **Step 8.5: Commit**

```bash
git add internal/probe/dns.go internal/probe/dns_test.go
git commit -m "probe: ReverseDNS PTR lookup with context"
```

---

## Task 9: scanner Worker interfaces and Merger

**Files:**
- Create: `internal/scanner/interfaces.go`
- Create: `internal/scanner/merger.go`
- Create: `internal/scanner/merger_test.go`

This is the heart of the system. The merger owns the device map and is fully testable using fake workers.

- [ ] **Step 9.1: Define worker-input message types and interface**

`internal/scanner/interfaces.go`:

```go
package scanner

import (
	"context"
	"net"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

// Update is what a Worker emits to the merger. Every field except Source is
// optional; the merger merges non-zero fields into the Device.
type Update struct {
	Source     string             // "arp" | "mdns" | "active"
	Time       time.Time          // when the observation happened
	MAC        string             // lowercase, colon-separated; "" if unknown
	IP         net.IP             // required for nearly every update
	Hostname   string             // mDNS or rDNS
	Vendor     string             // OUI lookup may have already been applied
	OSGuess    string             // active prober only
	OpenPorts  []model.Port       // active prober only; empty replaces existing
	Services   []model.ServiceInst // mDNS only; appended/deduped
	RTT        time.Duration      // active prober only
	Alive      bool               // active prober: is the device responding?
}

// A Worker emits Updates on its output channel until the context is cancelled.
// Implementations: arpWorker, mdnsWorker, activeWorker.
type Worker interface {
	Run(ctx context.Context, out chan<- Update) error
}
```

- [ ] **Step 9.2: Write failing tests for the merger**

`internal/scanner/merger_test.go`:

```go
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
```

- [ ] **Step 9.3: Run tests to verify they fail**

```bash
go test ./internal/scanner/ -v -run TestMerger
```

Expected: FAIL — package does not exist.

- [ ] **Step 9.4: Implement merger.go**

`internal/scanner/merger.go`:

```go
package scanner

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

// MergerOptions tunes the merger's timing behavior.
type MergerOptions struct {
	StaleAfter    time.Duration // Online → Stale after this idle period (default 60s)
	LeftAfter     time.Duration // Stale → Offline + emit Left after this idle period (default 5m)
	SweepInterval time.Duration // how often to scan for status transitions (default 30s)
}

func (o *MergerOptions) defaults() {
	if o.StaleAfter == 0 {
		o.StaleAfter = 60 * time.Second
	}
	if o.LeftAfter == 0 {
		o.LeftAfter = 5 * time.Minute
	}
	if o.SweepInterval == 0 {
		o.SweepInterval = 30 * time.Second
	}
}

// Merger owns the live device map and emits DeviceEvents.
type Merger struct {
	opts MergerOptions

	mu      sync.RWMutex
	byMAC   map[string]*model.Device
	byIP    map[string]*model.Device // for MAC-less entries
}

// NewMerger constructs an idle merger; call Run to start consuming updates.
func NewMerger(opts MergerOptions) *Merger {
	opts.defaults()
	return &Merger{
		opts:  opts,
		byMAC: make(map[string]*model.Device),
		byIP:  make(map[string]*model.Device),
	}
}

// Snapshot returns a copy of all devices in arbitrary order.
func (m *Merger) Snapshot() []*model.Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*model.Device, 0, len(m.byMAC)+len(m.byIP))
	for _, d := range m.byMAC {
		cp := *d
		out = append(out, &cp)
	}
	for _, d := range m.byIP {
		cp := *d
		out = append(out, &cp)
	}
	return out
}

// Run consumes updates from in and publishes events to out. Returns when ctx
// is cancelled.
func (m *Merger) Run(ctx context.Context, in <-chan Update, out chan<- model.DeviceEvent) {
	ticker := time.NewTicker(m.opts.SweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-in:
			if !ok {
				return
			}
			m.handleUpdate(u, out)
		case now := <-ticker.C:
			m.sweepStatus(now, out)
		}
	}
}

func (m *Merger) handleUpdate(u Update, out chan<- model.DeviceEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	mac := strings.ToLower(u.MAC)
	ipKey := ""
	if u.IP != nil {
		ipKey = u.IP.String()
	}

	var dev *model.Device
	created := false

	switch {
	case mac != "":
		// MAC-keyed path. If we have a preceding IP-only entry for this IP, fold it in.
		if existing, ok := m.byMAC[mac]; ok {
			dev = existing
		} else {
			dev = &model.Device{MAC: mac, FirstSeen: u.Time, Status: model.StatusOnline}
			created = true
			m.byMAC[mac] = dev
		}
		// Migrate IP-only entry if present
		if ipKey != "" {
			if old, ok := m.byIP[ipKey]; ok && old != dev {
				mergeFromIPOnly(dev, old)
				delete(m.byIP, ipKey)
			}
		}
	case ipKey != "":
		if existing, ok := m.byIP[ipKey]; ok {
			dev = existing
		} else {
			dev = &model.Device{FirstSeen: u.Time, Status: model.StatusOnline}
			created = true
			m.byIP[ipKey] = dev
		}
	default:
		return // can't key this update
	}

	mergeUpdate(dev, u)

	evt := model.DeviceEvent{Device: copyDevice(dev)}
	if created {
		evt.Type = model.EventJoined
	} else {
		evt.Type = model.EventUpdated
	}
	select {
	case out <- evt:
	default:
		// drop if consumer is slow; the live map is still authoritative
	}
}

// sweepStatus updates device statuses based on age (now - LastSeen):
//   - Online (≤ StaleAfter)
//   - Stale  (StaleAfter < age ≤ LeftAfter)
//   - Offline (age > LeftAfter) — emits EventLeft on the transition
func (m *Merger) sweepStatus(now time.Time, out chan<- model.DeviceEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	staleCut := now.Add(-m.opts.StaleAfter)
	leftCut := now.Add(-m.opts.LeftAfter)

	transition := func(d *model.Device) {
		switch {
		case d.LastSeen.Before(leftCut):
			if d.Status != model.StatusOffline {
				d.Status = model.StatusOffline
				select {
				case out <- model.DeviceEvent{Type: model.EventLeft, Device: copyDevice(d)}:
				default:
				}
			}
		case d.LastSeen.Before(staleCut):
			if d.Status == model.StatusOnline {
				d.Status = model.StatusStale
			}
		}
	}
	for _, d := range m.byMAC {
		transition(d)
	}
	for _, d := range m.byIP {
		transition(d)
	}
}

// mergeUpdate applies non-zero fields of u onto dev.
func mergeUpdate(dev *model.Device, u Update) {
	if u.IP != nil {
		if !containsIP(dev.IPs, u.IP) {
			dev.IPs = append(dev.IPs, u.IP)
		}
	}
	if u.MAC != "" && dev.MAC == "" {
		dev.MAC = strings.ToLower(u.MAC)
	}
	if u.Hostname != "" {
		dev.Hostname = u.Hostname
	}
	if u.Vendor != "" {
		dev.Vendor = u.Vendor
	}
	if u.OSGuess != "" {
		dev.OSGuess = u.OSGuess
	}
	if u.OpenPorts != nil {
		dev.OpenPorts = u.OpenPorts
	}
	for _, s := range u.Services {
		if !containsService(dev.Services, s) {
			dev.Services = append(dev.Services, s)
		}
	}
	if u.RTT > 0 {
		dev.RTT = u.RTT
		dev.RTTHistory = append(dev.RTTHistory, u.RTT)
		if len(dev.RTTHistory) > 10 {
			dev.RTTHistory = dev.RTTHistory[len(dev.RTTHistory)-10:]
		}
	}
	if u.Time.After(dev.LastSeen) {
		dev.LastSeen = u.Time
	}
	if dev.FirstSeen.IsZero() {
		dev.FirstSeen = u.Time
	}
	// Any received update means we just heard from the device — Online.
	// The sweep handles decay back to Stale/Offline based on age.
	dev.Status = model.StatusOnline
	sort.Slice(dev.OpenPorts, func(i, j int) bool { return dev.OpenPorts[i].Number < dev.OpenPorts[j].Number })
}

func mergeFromIPOnly(dst, src *model.Device) {
	for _, ip := range src.IPs {
		if !containsIP(dst.IPs, ip) {
			dst.IPs = append(dst.IPs, ip)
		}
	}
	if dst.Hostname == "" {
		dst.Hostname = src.Hostname
	}
	if dst.OSGuess == "" {
		dst.OSGuess = src.OSGuess
	}
	if len(dst.OpenPorts) == 0 {
		dst.OpenPorts = src.OpenPorts
	}
	for _, s := range src.Services {
		if !containsService(dst.Services, s) {
			dst.Services = append(dst.Services, s)
		}
	}
	if dst.RTT == 0 {
		dst.RTT = src.RTT
	}
	if len(dst.RTTHistory) == 0 {
		dst.RTTHistory = src.RTTHistory
	}
	if src.FirstSeen.Before(dst.FirstSeen) || dst.FirstSeen.IsZero() {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen.After(dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
}

func containsIP(list []net.IP, ip net.IP) bool {
	for _, x := range list {
		if x.Equal(ip) {
			return true
		}
	}
	return false
}

func containsService(list []model.ServiceInst, s model.ServiceInst) bool {
	for _, x := range list {
		if x.Type == s.Type && x.Name == s.Name && x.Port == s.Port {
			return true
		}
	}
	return false
}

func copyDevice(d *model.Device) *model.Device {
	cp := *d
	cp.IPs = append([]net.IP(nil), d.IPs...)
	cp.OpenPorts = append([]model.Port(nil), d.OpenPorts...)
	cp.Services = append([]model.ServiceInst(nil), d.Services...)
	cp.RTTHistory = append([]time.Duration(nil), d.RTTHistory...)
	return &cp
}
```

- [ ] **Step 9.5: Run tests to verify they pass**

```bash
go test ./internal/scanner/ -v
```

Expected: PASS for all four merger tests.

- [ ] **Step 9.6: Commit**

```bash
git add internal/scanner/interfaces.go internal/scanner/merger.go internal/scanner/merger_test.go
git commit -m "scanner: Worker interface + Merger with MAC/IP keying and Left timeout"
```

---

## Task 10: scanner.ARP worker

**Files:**
- Create: `internal/scanner/arp.go`

This worker is hardware-dependent and not unit-tested. The merger tests already exercise the data path with synthetic ARP-shaped updates.

- [ ] **Step 10.1: Add gopacket dependency**

```bash
go get github.com/google/gopacket
```

- [ ] **Step 10.2: Implement arp.go**

`internal/scanner/arp.go`:

```go
package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/lab1702/lan-inventory/internal/oui"
)

// ARPWorker passively sniffs ARP packets on the given interface and emits an
// Update for every packet seen.
type ARPWorker struct {
	IfaceName string
}

func (w *ARPWorker) Run(ctx context.Context, out chan<- Update) error {
	handle, err := pcap.OpenLive(w.IfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open %s: %w (do you have CAP_NET_RAW?)", w.IfaceName, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		return fmt.Errorf("set bpf filter: %w", err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := src.Packets()

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt, ok := <-packets:
			if !ok {
				return nil
			}
			arpLayer := pkt.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp, ok := arpLayer.(*layers.ARP)
			if !ok {
				continue
			}
			mac := net.HardwareAddr(arp.SourceHwAddress).String()
			ip := net.IP(arp.SourceProtAddress)
			if mac == "" || ip == nil || ip.IsUnspecified() {
				continue
			}
			update := Update{
				Source: "arp",
				Time:   time.Now(),
				MAC:    strings.ToLower(mac),
				IP:     ip,
				Vendor: oui.Lookup(mac),
			}
			select {
			case out <- update:
			case <-ctx.Done():
				return nil
			}
		}
	}
}
```

- [ ] **Step 10.3: Verify it builds**

```bash
go build ./...
```

Expected: builds without errors. (libpcap-dev must be installed on the build host.)

- [ ] **Step 10.4: Commit**

```bash
git add internal/scanner/arp.go go.mod go.sum
git commit -m "scanner: ARPWorker passive sniff with gopacket + OUI vendor enrichment"
```

---

## Task 11: scanner.MDNS worker

**Files:**
- Create: `internal/scanner/mdns.go`

- [ ] **Step 11.1: Add zeroconf dependency**

```bash
go get github.com/grandcat/zeroconf
```

- [ ] **Step 11.2: Implement mdns.go**

`internal/scanner/mdns.go`:

```go
package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/grandcat/zeroconf"

	"github.com/lab1702/lan-inventory/internal/model"
)

// MDNSWorker browses for mDNS services on the given interface and emits an
// Update for each discovered instance.
type MDNSWorker struct {
	IfaceName string
}

// commonServiceTypes is the seed list we actively browse for. zeroconf doesn't
// support a single "browse everything" query well, so we enumerate a handful
// of widely-deployed services. Additional services that announce themselves
// via gratuitous packets will still be observed.
var commonServiceTypes = []string{
	"_http._tcp",
	"_https._tcp",
	"_ssh._tcp",
	"_airplay._tcp",
	"_googlecast._tcp",
	"_printer._tcp",
	"_ipp._tcp",
	"_smb._tcp",
	"_workstation._tcp",
}

func (w *MDNSWorker) Run(ctx context.Context, out chan<- Update) error {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return fmt.Errorf("zeroconf resolver: %w", err)
	}

	for _, svc := range commonServiceTypes {
		svc := svc
		entries := make(chan *zeroconf.ServiceEntry, 16)
		go w.consume(ctx, svc, entries, out)
		go func() {
			if err := resolver.Browse(ctx, svc, "local.", entries); err != nil {
				return
			}
		}()
	}
	<-ctx.Done()
	return nil
}

func (w *MDNSWorker) consume(ctx context.Context, svc string, entries <-chan *zeroconf.ServiceEntry, out chan<- Update) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-entries:
			if !ok {
				return
			}
			update := Update{
				Source:   "mdns",
				Time:     time.Now(),
				Hostname: trimDot(e.HostName),
				Services: []model.ServiceInst{
					{Type: svc, Name: e.Instance, Port: e.Port},
				},
			}
			if len(e.AddrIPv4) > 0 {
				update.IP = pickFirstIP(e.AddrIPv4)
			}
			select {
			case out <- update:
			case <-ctx.Done():
				return
			}
		}
	}
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func pickFirstIP(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	return nil
}
```

- [ ] **Step 11.3: Verify it builds**

```bash
go build ./...
```

Expected: builds without errors.

- [ ] **Step 11.4: Commit**

```bash
git add internal/scanner/mdns.go go.mod go.sum
git commit -m "scanner: MDNSWorker browses common service types via zeroconf"
```

---

## Task 12: scanner.Active worker

**Files:**
- Create: `internal/scanner/active.go`

- [ ] **Step 12.1: Implement active.go**

`internal/scanner/active.go`:

```go
package scanner

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/lab1702/lan-inventory/internal/probe"
)

// ActiveWorker periodically probes every host in Subnet plus any IP it has
// learned about, calling probe.Ping, probe.ScanPorts, and probe.ReverseDNS.
// One full sweep emits one Update per responding host.
type ActiveWorker struct {
	Subnet      *net.IPNet
	HostIPs     []net.IP // pre-enumerated subnet hosts
	Interval    time.Duration
	WorkerCount int
}

func (w *ActiveWorker) Run(ctx context.Context, out chan<- Update) error {
	if w.Interval == 0 {
		w.Interval = 30 * time.Second
	}
	if w.WorkerCount == 0 {
		w.WorkerCount = 32
	}

	// Run an initial sweep immediately, then on the interval.
	w.sweepOnce(ctx, out)
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.sweepOnce(ctx, out)
		}
	}
}

// SweepOnce probes every host once and returns when the sweep finishes. Used
// directly by --once mode.
func (w *ActiveWorker) SweepOnce(ctx context.Context, out chan<- Update) {
	w.sweepOnce(ctx, out)
}

func (w *ActiveWorker) sweepOnce(ctx context.Context, out chan<- Update) {
	jobs := make(chan net.IP, len(w.HostIPs))
	var wg sync.WaitGroup
	for i := 0; i < w.WorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				w.probeOne(ctx, ip, out)
			}
		}()
	}
	for _, ip := range w.HostIPs {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
}

func (w *ActiveWorker) probeOne(ctx context.Context, ip net.IP, out chan<- Update) {
	if ctx.Err() != nil {
		return
	}
	pingRes, err := probe.Ping(ctx, ip.String())
	if err != nil || !pingRes.Alive {
		// No signal from this host this cycle — emit nothing. Status decay
		// happens via the merger's age-based sweep.
		return
	}
	update := Update{
		Source:    "active",
		Time:      time.Now(),
		IP:        ip,
		Alive:     true,
		RTT:       pingRes.RTT,
		OSGuess:   probe.OSGuess(pingRes.TTL),
		Hostname:  probe.ReverseDNS(ctx, ip.String()),
		OpenPorts: probe.ScanPorts(ctx, ip.String(), probe.DefaultPorts(), 500*time.Millisecond),
	}
	select {
	case out <- update:
	case <-ctx.Done():
	}
}
```

- [ ] **Step 12.2: Verify it builds**

```bash
go build ./...
```

Expected: builds.

- [ ] **Step 12.3: Commit**

```bash
git add internal/scanner/active.go
git commit -m "scanner: ActiveWorker periodic probe sweep with worker pool"
```

---

## Task 13: scanner.Scanner top-level

**Files:**
- Create: `internal/scanner/scanner.go`

- [ ] **Step 13.1: Implement scanner.go**

`internal/scanner/scanner.go`:

```go
package scanner

import (
	"context"
	"sync"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/netiface"
)

// Config describes the scanner's runtime parameters.
type Config struct {
	Iface         *netiface.Info
	MergerOptions MergerOptions
	OnceMode      bool // if true, ActiveWorker runs a single sweep then context is cancelled by the caller
}

// Scanner wires the three workers and the merger together.
type Scanner struct {
	cfg     Config
	merger  *Merger
	events  chan model.DeviceEvent
	updates chan Update
	active  *ActiveWorker
}

// New builds a fresh Scanner. Call Run to start it.
func New(cfg Config) *Scanner {
	return &Scanner{
		cfg:     cfg,
		merger:  NewMerger(cfg.MergerOptions),
		events:  make(chan model.DeviceEvent, 256),
		updates: make(chan Update, 256),
	}
}

// TriggerSweep runs a single out-of-band active sweep using the same worker
// pool as the periodic scan. Safe to call concurrently with Run.
func (s *Scanner) TriggerSweep(ctx context.Context) {
	if s.active == nil {
		return
	}
	s.active.SweepOnce(ctx, s.updates)
}

// Events returns a read-only channel of DeviceEvent.
func (s *Scanner) Events() <-chan model.DeviceEvent { return s.events }

// Snapshot returns a copy of the current device map.
func (s *Scanner) Snapshot() []*model.Device { return s.merger.Snapshot() }

// Run starts the workers and the merger. Blocks until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) error {
	hosts := netiface.SubnetIPs(s.cfg.Iface.Subnet)

	arp := &ARPWorker{IfaceName: s.cfg.Iface.Name}
	mdns := &MDNSWorker{IfaceName: s.cfg.Iface.Name}
	s.active = &ActiveWorker{
		Subnet:      s.cfg.Iface.Subnet,
		HostIPs:     hosts,
		WorkerCount: 32,
	}
	active := s.active

	var wg sync.WaitGroup

	wg.Add(1)
	go func() { defer wg.Done(); s.merger.Run(ctx, s.updates, s.events) }()

	wg.Add(1)
	go func() { defer wg.Done(); _ = arp.Run(ctx, s.updates) }()

	wg.Add(1)
	go func() { defer wg.Done(); _ = mdns.Run(ctx, s.updates) }()

	wg.Add(1)
	go func() { defer wg.Done(); _ = active.Run(ctx, s.updates) }()

	wg.Wait()
	close(s.events)
	return nil
}
```

- [ ] **Step 13.2: Verify it builds**

```bash
go build ./...
```

Expected: builds.

- [ ] **Step 13.3: Commit**

```bash
git add internal/scanner/scanner.go
git commit -m "scanner: top-level wiring of ARP + mDNS + Active + Merger"
```

---

## Task 14: snapshot.JSON writer

**Files:**
- Create: `internal/snapshot/snapshot.go`
- Create: `internal/snapshot/snapshot_test.go`

- [ ] **Step 14.1: Write failing test**

`internal/snapshot/snapshot_test.go`:

```go
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
```

- [ ] **Step 14.2: Run test to verify it fails**

```bash
go test ./internal/snapshot/ -v
```

Expected: FAIL — package does not exist.

- [ ] **Step 14.3: Implement snapshot.go**

`internal/snapshot/snapshot.go`:

```go
// Package snapshot renders the scanner's current device map as JSON or as a
// human-readable text table for the --once mode.
package snapshot

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

// Header is the metadata stamped onto a JSON snapshot.
type Header struct {
	ScannedAt time.Time `json:"scanned_at"`
	Subnet    string    `json:"subnet"`
	Iface     string    `json:"interface"`
}

type jsonDoc struct {
	Header
	Devices []*model.Device `json:"devices"`
}

// WriteJSON marshals the header and devices as a single JSON object.
func WriteJSON(w io.Writer, h Header, devices []*model.Device) error {
	doc := jsonDoc{Header: h, Devices: devices}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// WriteTable writes a fixed-width text table. If color is true and the
// underlying writer is a TTY, ANSI color codes are emitted for status.
func WriteTable(w io.Writer, devices []*model.Device, color bool) error {
	sorted := append([]*model.Device(nil), devices...)
	sort.Slice(sorted, func(i, j int) bool {
		return firstIPString(sorted[i]) < firstIPString(sorted[j])
	})

	header := []string{"IP", "MAC", "Vendor", "Hostname", "OS", "Ports", "RTT", "Status"}
	rows := [][]string{header}
	for _, d := range sorted {
		ports := portsCSV(d.OpenPorts)
		rows = append(rows, []string{
			firstIPString(d),
			d.MAC,
			truncate(d.Vendor, 14),
			truncate(d.Hostname, 22),
			truncate(d.OSGuess, 12),
			truncate(ports, 22),
			formatRTT(d.RTT),
			colorStatus(d.Status, color),
		})
	}
	widths := columnWidths(rows)
	for i, row := range rows {
		var b strings.Builder
		for j, cell := range row {
			b.WriteString(padRight(cell, widths[j]))
			if j != len(row)-1 {
				b.WriteString("  ")
			}
		}
		b.WriteString("\n")
		if i == 0 {
			b.WriteString(strings.Repeat("-", sum(widths)+2*(len(widths)-1)))
			b.WriteString("\n")
		}
		if _, err := io.WriteString(w, b.String()); err != nil {
			return err
		}
	}
	return nil
}

func firstIPString(d *model.Device) string {
	if len(d.IPs) == 0 {
		return ""
	}
	return d.IPs[0].String()
}

func portsCSV(ports []model.Port) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p.Number))
	}
	return strings.Join(parts, ",")
}

func formatRTT(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return d.Round(100 * time.Microsecond).String()
}

func colorStatus(s model.Status, color bool) string {
	label := s.String()
	if !color {
		return label
	}
	switch s {
	case model.StatusOnline:
		return "\x1b[32m" + label + "\x1b[0m"
	case model.StatusStale:
		return "\x1b[33m" + label + "\x1b[0m"
	case model.StatusOffline:
		return "\x1b[31m" + label + "\x1b[0m"
	}
	return label
}

func columnWidths(rows [][]string) []int {
	if len(rows) == 0 {
		return nil
	}
	w := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, cell := range row {
			if l := visibleLen(cell); l > w[i] {
				w[i] = l
			}
		}
	}
	return w
}

func visibleLen(s string) int {
	out := 0
	in := false
	for _, r := range s {
		if r == 0x1b {
			in = true
			continue
		}
		if in {
			if r == 'm' {
				in = false
			}
			continue
		}
		out++
	}
	return out
}

func padRight(s string, w int) string {
	pad := w - visibleLen(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

func sum(xs []int) int {
	s := 0
	for _, x := range xs {
		s += x
	}
	return s
}
```

- [ ] **Step 14.4: Run tests to verify they pass**

```bash
go test ./internal/snapshot/ -v
```

Expected: PASS for both `TestWriteJSON` and `TestWriteTable`.

- [ ] **Step 14.5: Commit**

```bash
git add internal/snapshot/
git commit -m "snapshot: WriteJSON and WriteTable for --once output"
```

---

## Task 15: TUI base model + tab switching

**Files:**
- Create: `internal/tui/model.go`
- Create: `internal/tui/tui_test.go`

- [ ] **Step 15.1: Add Bubble Tea + Lipgloss + teatest**

```bash
go get github.com/charmbracelet/bubbletea github.com/charmbracelet/lipgloss
go get github.com/charmbracelet/x/exp/teatest
```

- [ ] **Step 15.2: Write failing test for tab switching**

`internal/tui/tui_test.go`:

```go
package tui_test

import (
	"bytes"
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
	return tm.FinalOutput(t, teatest.WithFinalTimeout(wait))
}
```

- [ ] **Step 15.3: Run test to verify it fails**

```bash
go test ./internal/tui/ -v
```

Expected: FAIL — package does not exist.

- [ ] **Step 15.4: Implement model.go**

`internal/tui/model.go`:

```go
// Package tui implements the Bubble Tea TUI: a 4-tab dashboard over the
// scanner's live device map.
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/lab1702/lan-inventory/internal/model"
)

type tab int

const (
	tabDevices tab = iota
	tabServices
	tabSubnet
	tabEvents
)

// Deps wires runtime dependencies into the TUI. Empty values are tolerated for
// tests; production callers should supply Snapshot/Events.
type Deps struct {
	Subnet   string
	Iface    string
	Snapshot func() []*model.Device                // returns a fresh slice each call
	Events   func() <-chan model.DeviceEvent       // single-consumer channel of new events
}

// Model is the root Bubble Tea model.
type Model struct {
	deps Deps

	tab     tab
	devices []*model.Device
	events  []model.Event

	width  int
	height int

	// pollInterval controls how often the TUI re-snapshots the scanner.
	pollInterval time.Duration

	// for tests: explicitly track quit
	quitting bool
}

func NewModel(deps Deps) Model {
	return Model{
		deps:         deps,
		tab:          tabDevices,
		pollInterval: 1 * time.Second,
	}
}

// Init starts the snapshot poll ticker and event subscription.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{tickCmd(m.pollInterval)}
	if m.deps.Events != nil {
		cmds = append(cmds, listenEvents(m.deps.Events()))
	}
	return tea.Batch(cmds...)
}

type tickMsg time.Time

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

type eventMsg model.DeviceEvent

func listenEvents(ch <-chan model.DeviceEvent) tea.Cmd {
	return func() tea.Msg {
		e, ok := <-ch
		if !ok {
			return nil
		}
		return eventMsg(e)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "1":
			m.tab = tabDevices
		case "2":
			m.tab = tabServices
		case "3":
			m.tab = tabSubnet
		case "4":
			m.tab = tabEvents
		}
	case tickMsg:
		if m.deps.Snapshot != nil {
			m.devices = m.deps.Snapshot()
		}
		return m, tickCmd(m.pollInterval)
	case eventMsg:
		evt := model.Event{Time: time.Now(), Type: msg.Type, MAC: msg.Device.MAC}
		if len(msg.Device.IPs) > 0 {
			evt.IP = msg.Device.IPs[0]
		}
		m.events = append([]model.Event{evt}, m.events...)
		if len(m.events) > 200 {
			m.events = m.events[:200]
		}
		if m.deps.Events != nil {
			return m, listenEvents(m.deps.Events())
		}
	}
	return m, nil
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")
	switch m.tab {
	case tabDevices:
		b.WriteString(m.viewDevices())
	case tabServices:
		b.WriteString(m.viewServices())
	case tabSubnet:
		b.WriteString(m.viewSubnet())
	case tabEvents:
		b.WriteString(m.viewEvents())
	}
	return b.String()
}

func (m Model) renderHeader() string {
	tabs := []string{"Devices", "Services", "Subnet", "Events"}
	rendered := make([]string, len(tabs))
	for i, name := range tabs {
		label := fmt.Sprintf("[%d] %s", i+1, name)
		if int(m.tab) == i {
			label = lipgloss.NewStyle().Bold(true).Underline(true).Render(label)
		}
		rendered[i] = label
	}
	stats := m.summaryLine()
	return strings.Join(rendered, "  ") + "\n" + stats
}

func (m Model) summaryLine() string {
	online, stale, offline := 0, 0, 0
	for _, d := range m.devices {
		switch d.Status {
		case model.StatusOnline:
			online++
		case model.StatusStale:
			stale++
		case model.StatusOffline:
			offline++
		}
	}
	return fmt.Sprintf("Online: %d   Stale: %d   Offline: %d   Subnet: %s   Iface: %s",
		online, stale, offline, m.deps.Subnet, m.deps.Iface)
}
```

- [ ] **Step 15.5: Add stub view functions for the four tabs (so the package compiles for the base test)**

`internal/tui/devices.go`:

```go
package tui

func (m Model) viewDevices() string { return renderDevicesPlaceholder() }

func renderDevicesPlaceholder() string { return "Devices" }
```

`internal/tui/services.go`:

```go
package tui

func (m Model) viewServices() string { return "Services" }
```

`internal/tui/subnet.go`:

```go
package tui

func (m Model) viewSubnet() string { return "Subnet" }
```

`internal/tui/events.go`:

```go
package tui

func (m Model) viewEvents() string { return "Events" }
```

- [ ] **Step 15.6: Run tests to verify they pass**

```bash
go test ./internal/tui/ -v
```

Expected: PASS for `TestQuitOnQ` and `TestSwitchTabs`.

- [ ] **Step 15.7: Commit**

```bash
git add internal/tui/ go.mod go.sum
git commit -m "tui: base model with header, tab switching, snapshot polling"
```

---

## Task 16: TUI Devices tab

**Files:**
- Modify: `internal/tui/devices.go`
- Modify: `internal/tui/tui_test.go` (append)

- [ ] **Step 16.1: Append failing test for the Devices tab content**

Append to `internal/tui/tui_test.go`:

```go
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
	out := tm.FinalOutput(t, teatest.WithFinalTimeout(2*time.Second))
	for _, want := range []string{"macbook.local", "192.168.1.10", "Apple"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("expected %q in Devices tab:\n%s", want, out)
		}
	}
}
```

Add the missing imports at top of `tui_test.go`: `"net"`, `"github.com/lab1702/lan-inventory/internal/model"`.

- [ ] **Step 16.2: Run test to verify it fails**

```bash
go test ./internal/tui/ -v -run TestDevicesTabRendersRows
```

Expected: FAIL — placeholder doesn't render rows.

- [ ] **Step 16.3: Implement devices.go**

Replace `internal/tui/devices.go`:

```go
package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

func (m Model) viewDevices() string {
	if len(m.devices) == 0 {
		return "(no devices yet — first scan in progress)"
	}
	devices := append([]*model.Device(nil), m.devices...)
	sort.Slice(devices, func(i, j int) bool { return firstIP(devices[i]) < firstIP(devices[j]) })

	var b strings.Builder
	header := fmt.Sprintf("%-15s  %-17s  %-12s  %-22s  %-12s  %-22s  %-8s  %s",
		"IP", "MAC", "Vendor", "Hostname", "OS", "Ports", "RTT", "Status")
	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", len(header)))
	b.WriteString("\n")
	for _, d := range devices {
		b.WriteString(fmt.Sprintf("%-15s  %-17s  %-12s  %-22s  %-12s  %-22s  %-8s  %s\n",
			firstIP(d),
			d.MAC,
			truncate(d.Vendor, 12),
			truncate(d.Hostname, 22),
			truncate(d.OSGuess, 12),
			truncate(portsCSV(d.OpenPorts), 22),
			rttString(d.RTT),
			d.Status,
		))
	}
	return b.String()
}

func firstIP(d *model.Device) string {
	if len(d.IPs) == 0 {
		return ""
	}
	return d.IPs[0].String()
}

func portsCSV(ports []model.Port) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p.Number))
	}
	return strings.Join(parts, ",")
}

func rttString(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return d.Round(100 * time.Microsecond).String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}
```

- [ ] **Step 16.4: Run test to verify it passes**

```bash
go test ./internal/tui/ -v
```

Expected: PASS for all TUI tests.

- [ ] **Step 16.5: Commit**

```bash
git add internal/tui/devices.go internal/tui/tui_test.go
git commit -m "tui: Devices tab with sorted IP table"
```

---

## Task 17: TUI Services tab

**Files:**
- Modify: `internal/tui/services.go`
- Modify: `internal/tui/tui_test.go` (append)

- [ ] **Step 17.1: Append failing test**

Append to `internal/tui/tui_test.go`:

```go
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
	out := tm.FinalOutput(t, teatest.WithFinalTimeout(2*time.Second))
	if !bytes.Contains(out, []byte("_http._tcp")) {
		t.Errorf("expected _http._tcp grouping:\n%s", out)
	}
	if !bytes.Contains(out, []byte("2 instances")) {
		t.Errorf("expected count summary:\n%s", out)
	}
}
```

- [ ] **Step 17.2: Run test to verify it fails**

```bash
go test ./internal/tui/ -v -run TestServicesTab
```

Expected: FAIL.

- [ ] **Step 17.3: Implement services.go**

Replace `internal/tui/services.go`:

```go
package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lab1702/lan-inventory/internal/model"
)

func (m Model) viewServices() string {
	groups := groupServices(m.devices)
	if len(groups) == 0 {
		return "(no services seen yet)"
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		hosts := groups[k]
		count := len(hosts)
		instLabel := "instance"
		if count != 1 {
			instLabel = "instances"
		}
		hostList := strings.Join(hosts, ", ")
		b.WriteString(fmt.Sprintf("%-22s  %d %s  →  %s\n", k, count, instLabel, hostList))
	}
	return b.String()
}

// groupServices builds map[serviceType] = []hostLabel from the devices.
// Service type can come from either mDNS Services or open-port labels.
func groupServices(devices []*model.Device) map[string][]string {
	groups := map[string]map[string]struct{}{}
	for _, d := range devices {
		host := d.Hostname
		if host == "" {
			host = firstIP(d)
		}
		for _, s := range d.Services {
			if _, ok := groups[s.Type]; !ok {
				groups[s.Type] = map[string]struct{}{}
			}
			groups[s.Type][host] = struct{}{}
		}
		for _, p := range d.OpenPorts {
			label := fmt.Sprintf("%d/%s", p.Number, p.Proto)
			if p.Service != "" {
				label = fmt.Sprintf("%d/%s (%s)", p.Number, p.Proto, p.Service)
			}
			if _, ok := groups[label]; !ok {
				groups[label] = map[string]struct{}{}
			}
			groups[label][host] = struct{}{}
		}
	}
	out := map[string][]string{}
	for k, set := range groups {
		hosts := make([]string, 0, len(set))
		for h := range set {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		out[k] = hosts
	}
	return out
}
```

- [ ] **Step 17.4: Run test to verify it passes**

```bash
go test ./internal/tui/ -v
```

Expected: PASS.

- [ ] **Step 17.5: Commit**

```bash
git add internal/tui/services.go internal/tui/tui_test.go
git commit -m "tui: Services tab grouped by service type with instance counts"
```

---

## Task 18: TUI Subnet tab

**Files:**
- Modify: `internal/tui/subnet.go`
- Modify: `internal/tui/tui_test.go` (append)

- [ ] **Step 18.1: Append failing test**

Append to `internal/tui/tui_test.go`:

```go
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
	out := tm.FinalOutput(t, teatest.WithFinalTimeout(2*time.Second))
	// The grid should render some non-empty content with at least one
	// online cell glyph.
	if !bytes.Contains(out, []byte("●")) && !bytes.Contains(out, []byte("·")) {
		t.Errorf("expected subnet grid glyphs:\n%s", out)
	}
}
```

- [ ] **Step 18.2: Run test to verify it fails**

```bash
go test ./internal/tui/ -v -run TestSubnetTab
```

Expected: FAIL.

- [ ] **Step 18.3: Implement subnet.go**

Replace `internal/tui/subnet.go`:

```go
package tui

import (
	"fmt"
	"net"
	"strings"

	"github.com/lab1702/lan-inventory/internal/model"
)

// viewSubnet renders the live subnet as a grid. For a /24, 16×16. For smaller
// subnets the grid auto-shrinks. For larger subnets up to /22, multiple /24
// blocks are stacked vertically.
func (m Model) viewSubnet() string {
	_, subnet, err := net.ParseCIDR(m.deps.Subnet)
	if err != nil || subnet == nil {
		return "(no subnet info)"
	}
	statusByLast := map[string]model.Status{}
	for _, d := range m.devices {
		for _, ip := range d.IPs {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if subnet.Contains(ip4) {
				statusByLast[ip4.String()] = d.Status
			}
		}
	}

	ones, _ := subnet.Mask.Size()
	if ones < 22 {
		return "(subnet too large to render)"
	}
	hostBits := 32 - ones
	gridSide := 1 << (hostBits / 2)
	if gridSide < 1 {
		gridSide = 1
	}
	gridOther := 1 << (hostBits - hostBits/2)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Subnet %s — %d hosts\n", m.deps.Subnet, 1<<hostBits))
	b.WriteString("Legend: ● online · stale x offline _ unseen\n\n")

	base := subnet.IP.Mask(subnet.Mask).To4()
	for row := 0; row < gridOther; row++ {
		for col := 0; col < gridSide; col++ {
			offset := row*gridSide + col
			ip := make(net.IP, 4)
			copy(ip, base)
			carry := offset
			for i := 3; i >= 0 && carry > 0; i-- {
				sum := int(ip[i]) + carry
				ip[i] = byte(sum & 0xff)
				carry = sum >> 8
			}
			glyph := "_"
			switch statusByLast[ip.String()] {
			case model.StatusOnline:
				glyph = "●"
			case model.StatusStale:
				glyph = "·"
			case model.StatusOffline:
				glyph = "x"
			}
			b.WriteString(glyph)
		}
		b.WriteString("\n")
	}
	return b.String()
}
```

- [ ] **Step 18.4: Run test to verify it passes**

```bash
go test ./internal/tui/ -v
```

Expected: PASS.

- [ ] **Step 18.5: Commit**

```bash
git add internal/tui/subnet.go internal/tui/tui_test.go
git commit -m "tui: Subnet tab grid scaling from /22 to /32"
```

---

## Task 19: TUI Events tab

**Files:**
- Modify: `internal/tui/events.go`
- Modify: `internal/tui/tui_test.go` (append)

- [ ] **Step 19.1: Append failing test**

Append to `internal/tui/tui_test.go`:

```go
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
	out := tm.FinalOutput(t, teatest.WithFinalTimeout(2*time.Second))
	if !bytes.Contains(out, []byte("aa:bb:cc:dd:ee:99")) {
		t.Errorf("expected event row in Events tab:\n%s", out)
	}
	if !bytes.Contains(out, []byte("joined")) {
		t.Errorf("expected joined label:\n%s", out)
	}
}
```

- [ ] **Step 19.2: Run test to verify it fails**

```bash
go test ./internal/tui/ -v -run TestEventsTab
```

Expected: FAIL.

- [ ] **Step 19.3: Implement events.go**

Replace `internal/tui/events.go`:

```go
package tui

import (
	"fmt"
	"strings"
)

func (m Model) viewEvents() string {
	if len(m.events) == 0 {
		return "(no events yet)"
	}
	var b strings.Builder
	for _, e := range m.events {
		ip := ""
		if e.IP != nil {
			ip = e.IP.String()
		}
		b.WriteString(fmt.Sprintf("%s  %-7s  %-18s  %s\n",
			e.Time.Format("15:04:05"),
			e.Type,
			e.MAC,
			ip,
		))
	}
	return b.String()
}
```

- [ ] **Step 19.4: Run test to verify it passes**

```bash
go test ./internal/tui/ -v
```

Expected: PASS.

- [ ] **Step 19.5: Commit**

```bash
git add internal/tui/events.go internal/tui/tui_test.go
git commit -m "tui: Events tab renders the in-session ring buffer"
```

---

## Task 20: cmd/lan-inventory main wiring

**Files:**
- Modify: `cmd/lan-inventory/main.go`
- Create: `internal/scanner/precheck.go`

- [ ] **Step 20.1: Add privilege precheck helper**

`internal/scanner/precheck.go`:

```go
package scanner

import (
	"errors"
	"fmt"

	"github.com/google/gopacket/pcap"
)

// ErrNoRawSocket is returned by Precheck when raw-socket access is missing.
var ErrNoRawSocket = errors.New("raw socket access denied")

// Precheck verifies that the calling process can open libpcap on the named
// interface. It is a fast smoke test that pcap_open_live succeeds — exactly
// the same call ARPWorker will make. If it fails, the user has no raw socket
// privilege, and the rest of the program will be useless.
func Precheck(ifaceName string) error {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoRawSocket, err)
	}
	handle.Close()
	return nil
}
```

- [ ] **Step 20.2: Replace main.go with full wiring**

`cmd/lan-inventory/main.go`:

```go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/lab1702/lan-inventory/internal/model"
	"github.com/lab1702/lan-inventory/internal/netiface"
	"github.com/lab1702/lan-inventory/internal/scanner"
	"github.com/lab1702/lan-inventory/internal/snapshot"
	"github.com/lab1702/lan-inventory/internal/tui"
)

const version = "0.1.0"

const (
	exitOK         = 0
	exitRuntime    = 1
	exitConfig     = 2
	exitNoDevices  = 3
)

func main() {
	once := flag.Bool("once", false, "run a single scan, print result, exit")
	table := flag.Bool("table", false, "with --once: print human-readable table instead of JSON")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("lan-inventory %s\n", version)
		os.Exit(exitOK)
	}

	iface, err := netiface.Detect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", err)
		os.Exit(exitConfig)
	}

	if err := scanner.Precheck(iface.Name); err != nil {
		fmt.Fprintln(os.Stderr, "lan-inventory: needs raw socket access to sniff ARP and send ICMP.")
		fmt.Fprintln(os.Stderr, "Either run with sudo, or grant capabilities once:")
		fmt.Fprintln(os.Stderr, "    sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-inventory)")
		os.Exit(exitConfig)
	}

	if *once {
		os.Exit(runOnce(iface, *table))
	}
	os.Exit(runTUI(iface))
}

func runOnce(iface *netiface.Info, asTable bool) int {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	scn := scanner.New(scanner.Config{Iface: iface, OnceMode: true})
	doneEvents := make(chan struct{})
	go func() {
		for range scn.Events() {
		}
		close(doneEvents)
	}()
	go scn.Run(ctx)

	// Spec: "starts ARP and mDNS listeners, waits 8 seconds for passive
	// signals, runs one full active sweep, snapshots, and exits." The
	// ActiveWorker kicks off its initial sweep on Run(); a full /24 sweep
	// with 32 workers and 1 s per-host ping timeout takes up to ~15 s for
	// fully dead subnets. We give the whole thing 20 s of wall time, which
	// covers passive warmup + active sweep on typical home LANs.
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
	cancel()
	<-doneEvents

	devices := scn.Snapshot()
	if len(devices) == 0 {
		fmt.Fprintln(os.Stderr, "lan-inventory: no devices discovered")
		return exitNoDevices
	}

	header := snapshot.Header{
		ScannedAt: time.Now().UTC(),
		Subnet:    iface.Subnet.String(),
		Iface:     iface.Name,
	}
	if asTable {
		isTTY := isTerminal(os.Stdout)
		if err := snapshot.WriteTable(os.Stdout, devices, isTTY); err != nil {
			fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", err)
			return exitRuntime
		}
	} else {
		if err := snapshot.WriteJSON(os.Stdout, header, devices); err != nil {
			fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", err)
			return exitRuntime
		}
	}
	return exitOK
}

func runTUI(iface *netiface.Info) int {
	ctx, cancel := signalContext()
	defer cancel()

	scn := scanner.New(scanner.Config{Iface: iface})
	go scn.Run(ctx)

	deps := tui.Deps{
		Subnet:   iface.Subnet.String(),
		Iface:    iface.Name,
		Snapshot: scn.Snapshot,
		Events:   func() <-chan model.DeviceEvent { return scn.Events() },
		OnRescan: func() { go scn.TriggerSweep(ctx) },
	}
	prog := tea.NewProgram(tui.NewModel(deps), tea.WithAltScreen())
	if _, err := prog.Run(); err != nil {
		if errors.Is(err, context.Canceled) {
			return exitOK
		}
		fmt.Fprintf(os.Stderr, "lan-inventory: %v\n", err)
		return exitRuntime
	}
	return exitOK
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
```

- [ ] **Step 20.3: Verify it builds**

```bash
go build ./...
```

Expected: builds successfully.

- [ ] **Step 20.4: Verify --version works without raw socket privilege**

```bash
./lan-inventory --version
```

Expected: prints `lan-inventory 0.1.0` and exits 0. Then delete the binary: `rm -f lan-inventory`.

- [ ] **Step 20.5: Run full test suite**

```bash
go test ./...
```

Expected: PASS for all unit tests across packages.

- [ ] **Step 20.6: Commit**

```bash
git add cmd/lan-inventory/main.go internal/scanner/precheck.go
git commit -m "cmd: privilege precheck, runOnce, runTUI, signal handling, exit codes"
```

---

## Task 21: TUI key bindings — sort, filter, rescan, drill, help

**Files:**
- Modify: `internal/tui/model.go`
- Modify: `internal/tui/devices.go`
- Modify: `internal/tui/tui_test.go` (append)

The spec calls out `s` cycle sort, `/` filter, `r` rescan, `Enter` drill-down, `?` help overlay. We add these on the Devices tab, since that's where they're most useful. The detail strip lives at the bottom of the Devices tab when a row is selected.

- [ ] **Step 21.1: Append failing tests**

Append to `internal/tui/tui_test.go`:

```go
func TestSortCycleByKey(t *testing.T) {
	devices := []*model.Device{
		{IPs: []net.IP{net.ParseIP("192.168.1.20")}, Hostname: "alpha"},
		{IPs: []net.IP{net.ParseIP("192.168.1.10")}, Hostname: "zebra"},
	}
	mod := tui.NewModel(tui.Deps{Subnet: "192.168.1.0/24", Iface: "eth0", Snapshot: func() []*model.Device { return devices }})
	tm := teatest.NewTestModel(t, mod, teatest.WithInitialTermSize(120, 40))
	defer tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})

	time.Sleep(1500 * time.Millisecond) // initial render with default sort (IP)
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}}) // cycle to Hostname
	time.Sleep(500 * time.Millisecond)
	out := tm.FinalOutput(t, teatest.WithFinalTimeout(2*time.Second))
	// After cycling to hostname-sort, "alpha" should appear before "zebra".
	alpha := bytes.Index(out, []byte("alpha"))
	zebra := bytes.Index(out, []byte("zebra"))
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
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	time.Sleep(500 * time.Millisecond)

	out := tm.FinalOutput(t, teatest.WithFinalTimeout(2*time.Second))
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
	out := tm.FinalOutput(t, teatest.WithFinalTimeout(2*time.Second))
	for _, want := range []string{"Help", "1-4", "/", "s", "r", "Enter"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("expected %q in help overlay:\n%s", want, out)
		}
	}
}
```

- [ ] **Step 21.2: Run tests to verify they fail**

```bash
go test ./internal/tui/ -v -run "TestSortCycle|TestFilterMode|TestHelpOverlay"
```

Expected: FAIL — features not yet implemented.

- [ ] **Step 21.3: Extend Model with sort key, filter buffer, selection, help flag**

Replace the `Model` struct and add a `sortKey` enum in `internal/tui/model.go`. Replace the entire `Model` declaration block:

```go
type sortKey int

const (
	sortByIP sortKey = iota
	sortByHostname
	sortByVendor
	sortByRTT
	sortByLastSeen
)

func (k sortKey) String() string {
	return [...]string{"ip", "hostname", "vendor", "rtt", "last_seen"}[k]
}

// Model is the root Bubble Tea model.
type Model struct {
	deps Deps

	tab      tab
	devices  []*model.Device
	events   []model.Event

	width  int
	height int

	pollInterval time.Duration
	quitting     bool

	// Devices-tab interaction state
	sortKey      sortKey
	filterBuf    string  // current filter text
	filterMode   bool    // true while typing filter
	selectedRow  int     // selected device index after sort+filter
	rescanNonce  int     // bumped by 'r' to signal scanner (consumed via Deps.OnRescan)

	// help overlay
	showHelp bool
}
```

Add a `Deps.OnRescan func()` field for the rescan signal:

```go
type Deps struct {
	Subnet    string
	Iface     string
	Snapshot  func() []*model.Device
	Events    func() <-chan model.DeviceEvent
	OnRescan  func() // optional: called when user presses 'r'
}
```

- [ ] **Step 21.4: Extend the Update method with the new key handling**

Replace the `case tea.KeyMsg:` block in `Update` with:

```go
case tea.KeyMsg:
	if m.filterMode {
		switch msg.Type {
		case tea.KeyEnter, tea.KeyEsc:
			m.filterMode = false
		case tea.KeyBackspace:
			if n := len(m.filterBuf); n > 0 {
				m.filterBuf = m.filterBuf[:n-1]
			}
		case tea.KeyRunes:
			m.filterBuf += string(msg.Runes)
		}
		return m, nil
	}
	if m.showHelp {
		m.showHelp = false
		return m, nil
	}
	switch msg.String() {
	case "q", "esc", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "1":
		m.tab = tabDevices
	case "2":
		m.tab = tabServices
	case "3":
		m.tab = tabSubnet
	case "4":
		m.tab = tabEvents
	case "s":
		m.sortKey = (m.sortKey + 1) % 5
	case "/":
		m.filterMode = true
		m.filterBuf = ""
	case "r":
		m.rescanNonce++
		if m.deps.OnRescan != nil {
			m.deps.OnRescan()
		}
	case "?":
		m.showHelp = true
	case "up", "k":
		if m.selectedRow > 0 {
			m.selectedRow--
		}
	case "down", "j":
		m.selectedRow++
	}
```

- [ ] **Step 21.5: Render help overlay when toggled**

Modify `View()` so that when `m.showHelp` is true, it returns the help text instead of the tabs:

```go
func (m Model) View() string {
	if m.quitting {
		return ""
	}
	if m.showHelp {
		return helpText()
	}
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n\n")
	switch m.tab {
	case tabDevices:
		b.WriteString(m.viewDevices())
	case tabServices:
		b.WriteString(m.viewServices())
	case tabSubnet:
		b.WriteString(m.viewSubnet())
	case tabEvents:
		b.WriteString(m.viewEvents())
	}
	if m.filterMode || m.filterBuf != "" {
		b.WriteString(fmt.Sprintf("\n\n/filter: %s", m.filterBuf))
	}
	return b.String()
}

func helpText() string {
	return strings.Join([]string{
		"Help — lan-inventory",
		"",
		"  1-4         switch tabs (Devices / Services / Subnet / Events)",
		"  ↑/↓ or k/j  navigate selection",
		"  Enter       drill into selected device",
		"  s           cycle sort key (ip → hostname → vendor → rtt → last_seen)",
		"  /           start filter (typing narrows the device list; Enter applies)",
		"  r           force a rescan now",
		"  ?           toggle this help",
		"  q / Esc     quit",
		"",
		"Press any key to dismiss.",
	}, "\n")
}
```

- [ ] **Step 21.6: Update viewDevices to honor sortKey, filterBuf, and selectedRow**

Replace `viewDevices()` in `internal/tui/devices.go`:

```go
package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lab1702/lan-inventory/internal/model"
)

func (m Model) viewDevices() string {
	devices := filterDevices(m.devices, m.filterBuf)
	sortDevices(devices, m.sortKey)
	if len(devices) == 0 {
		return "(no devices match)"
	}
	if m.selectedRow >= len(devices) {
		m.selectedRow = len(devices) - 1
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Sort: %s   ", m.sortKey))
	b.WriteString(fmt.Sprintf("Selection: %d/%d\n\n", m.selectedRow+1, len(devices)))
	header := fmt.Sprintf("%-15s  %-17s  %-12s  %-22s  %-12s  %-22s  %-8s  %s",
		"IP", "MAC", "Vendor", "Hostname", "OS", "Ports", "RTT", "Status")
	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", len(header)))
	b.WriteString("\n")
	for i, d := range devices {
		marker := "  "
		if i == m.selectedRow {
			marker = "> "
		}
		b.WriteString(marker)
		b.WriteString(fmt.Sprintf("%-15s  %-17s  %-12s  %-22s  %-12s  %-22s  %-8s  %s\n",
			firstIP(d),
			d.MAC,
			truncate(d.Vendor, 12),
			truncate(d.Hostname, 22),
			truncate(d.OSGuess, 12),
			truncate(portsCSV(d.OpenPorts), 22),
			rttString(d.RTT),
			d.Status,
		))
	}
	if len(devices) > 0 {
		b.WriteString("\n")
		b.WriteString(detailStrip(devices[m.selectedRow]))
	}
	return b.String()
}

func filterDevices(in []*model.Device, q string) []*model.Device {
	out := make([]*model.Device, 0, len(in))
	q = strings.ToLower(q)
	for _, d := range in {
		if q == "" || matchesFilter(d, q) {
			out = append(out, d)
		}
	}
	return out
}

func matchesFilter(d *model.Device, q string) bool {
	if strings.Contains(strings.ToLower(d.Hostname), q) {
		return true
	}
	if strings.Contains(strings.ToLower(d.MAC), q) {
		return true
	}
	if strings.Contains(strings.ToLower(d.Vendor), q) {
		return true
	}
	for _, ip := range d.IPs {
		if strings.Contains(ip.String(), q) {
			return true
		}
	}
	return false
}

func sortDevices(devs []*model.Device, key sortKey) {
	sort.SliceStable(devs, func(i, j int) bool {
		switch key {
		case sortByHostname:
			return devs[i].Hostname < devs[j].Hostname
		case sortByVendor:
			return devs[i].Vendor < devs[j].Vendor
		case sortByRTT:
			return devs[i].RTT < devs[j].RTT
		case sortByLastSeen:
			return devs[i].LastSeen.After(devs[j].LastSeen)
		default: // sortByIP
			return firstIP(devs[i]) < firstIP(devs[j])
		}
	})
}

func detailStrip(d *model.Device) string {
	var b strings.Builder
	b.WriteString("─── selected ─────────────────────────\n")
	b.WriteString(fmt.Sprintf("MAC:      %s\n", d.MAC))
	b.WriteString(fmt.Sprintf("Vendor:   %s\n", d.Vendor))
	b.WriteString(fmt.Sprintf("OS guess: %s\n", d.OSGuess))
	if len(d.OpenPorts) > 0 {
		ports := make([]string, 0, len(d.OpenPorts))
		for _, p := range d.OpenPorts {
			label := fmt.Sprintf("%d/%s", p.Number, p.Proto)
			if p.Service != "" {
				label += " (" + p.Service + ")"
			}
			ports = append(ports, label)
		}
		b.WriteString("Ports:    " + strings.Join(ports, ", ") + "\n")
	}
	if len(d.Services) > 0 {
		svcs := make([]string, 0, len(d.Services))
		for _, s := range d.Services {
			svcs = append(svcs, fmt.Sprintf("%s %q :%d", s.Type, s.Name, s.Port))
		}
		b.WriteString("Services: " + strings.Join(svcs, "; ") + "\n")
	}
	b.WriteString(fmt.Sprintf("First/Last seen: %s / %s\n",
		d.FirstSeen.Format(time.RFC3339), d.LastSeen.Format(time.RFC3339)))
	if len(d.RTTHistory) > 0 {
		samples := make([]string, 0, len(d.RTTHistory))
		for _, r := range d.RTTHistory {
			samples = append(samples, rttString(r))
		}
		b.WriteString("RTT history: " + strings.Join(samples, " ") + "\n")
	}
	return b.String()
}
```

- [ ] **Step 21.7: Run tests to verify they pass**

```bash
go test ./internal/tui/ -v
```

Expected: PASS for all TUI tests including the new ones.

- [ ] **Step 21.8: Commit**

```bash
git add internal/tui/
git commit -m "tui: sort cycle, filter mode, rescan signal, drill-down strip, help overlay"
```

---

## Task 22: Lint and CI

**Files:**
- Verify: `.github/workflows/ci.yml`

- [ ] **Step 22.1: Run go vet**

```bash
go vet ./...
```

Expected: no output (no warnings).

- [ ] **Step 22.2: Run staticcheck**

```bash
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
```

Expected: no warnings. Fix any reported issues — most likely candidates: unused variables, unreachable code, `error` returns ignored.

- [ ] **Step 22.3: Run full test suite once more**

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 22.4: Commit any lint fixes**

```bash
git add -u
git diff --cached --quiet && echo "no changes" || git commit -m "chore: address lint warnings"
```

---

## Task 23: README polish and smoke target

**Files:**
- Modify: `README.md`

- [ ] **Step 23.1: Expand README with the four commands and a screenshot placeholder**

Replace `README.md` with:

```markdown
# lan-inventory

A zero-config home-LAN inventory tool. Run it, see your network.

A single Go binary that auto-discovers devices on your local /24, presents a
live TUI dashboard, and can also dump a one-shot JSON or text snapshot for
scripts and cron.

## What it shows

- IP, MAC, vendor (OUI lookup)
- Hostname (mDNS preferred, reverse DNS fallback)
- OS family guess (TTL-based)
- Common open ports with service labels
- mDNS service announcements
- Last-seen timestamp and online/stale/offline status

## Install

```bash
go install github.com/lab1702/lan-inventory/cmd/lan-inventory@latest
sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-inventory)
```

Or build from source:

```bash
make build
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/lan-inventory
./bin/lan-inventory
```

The `setcap` step is needed once; `lan-inventory` requires raw-socket access
to sniff ARP packets and send ICMP ping. Without it the tool refuses to start.

## Usage

```bash
lan-inventory                 # interactive TUI dashboard
lan-inventory --once          # single scan, JSON to stdout, exit
lan-inventory --once --table  # single scan, human-readable table, exit
lan-inventory --version
```

### TUI keys

- `1`–`4` switch tabs (Devices / Services / Subnet / Events)
- `↑/↓` navigate
- `Enter` drill into a device
- `q` or `Esc` quit
- `?` help overlay

### Exit codes (non-interactive)

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Runtime error |
| 2    | Configuration error (no privilege, no default route, oversized subnet) |
| 3    | No devices discovered |

## Limitations

- IPv4 only.
- Targets /24 home networks; subnets larger than /22 are refused.
- No persistence: state is wiped on quit.
- Linux first; macOS support depends on libpcap availability.

## Development

```bash
make test     # run all unit tests
make vet      # go vet
make lint     # staticcheck
make smoke    # build, setcap, and run --once --table on your live network
```
```

- [ ] **Step 23.2: Verify build still works**

```bash
make build
```

Expected: produces `bin/lan-inventory`.

- [ ] **Step 23.3: Commit**

```bash
git add README.md
git commit -m "docs: README with install, usage, exit codes, limitations"
```

---

## Done

After all 23 tasks complete:

- `go test ./...` passes
- `go vet ./...` clean
- `staticcheck ./...` clean
- `./bin/lan-inventory --version` prints version
- `./bin/lan-inventory --once --table` (with setcap) prints a populated table
- `./bin/lan-inventory` (with setcap) launches the four-tab dashboard

The first usable v0.1.0 binary is in hand.
