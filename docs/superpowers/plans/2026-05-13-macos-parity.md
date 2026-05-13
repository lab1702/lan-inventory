# macOS parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the macOS build of `lan-inventory` to full feature parity with the existing Linux build — default-route detection, kernel-ARP-cache seed, unprivileged ICMP, pcap capture, mDNS, and the TUI.

**Architecture:** Add two `_darwin.go` files (one per package that currently has Linux/Windows splits), tighten the `_other.go` build tags from `!linux && !windows` to `!linux && !windows && !darwin`, change one line in `probe/ping_other.go` to make ICMP unprivileged on macOS, add a `case "darwin":` to the precheck error switch, add `macos-latest` to the CI matrix, and update the README. The merger, TUI, snapshot, and OUI packages are untouched.

**Tech Stack:** Go 1.24, `golang.org/x/net/route` (BSD route socket parser, already in go.sum as indirect dep), `github.com/google/gopacket/pcap` (already in use), `github.com/prometheus-community/pro-bing` (already in use). No new external dependencies.

---

## Development environment note

The primary development host is Windows. Darwin-tagged files cannot be compiled or tested locally on Windows without `GOOS=darwin` cross-compile. CI (`macos-latest`) is the verification path for actually running darwin tests; locally, use `GOOS=darwin go vet ./...` to catch compile errors before pushing.

Where a task says "run the failing test", on Windows that step becomes "cross-compile to confirm the file compiles and references the right symbols." The actual test execution happens in CI.

---

## File structure

**New files:**
- `internal/netiface/route_darwin.go` — default-route detection on macOS via `golang.org/x/net/route` + sysctl. Contains both the syscall wrapper and the pure helpers (`routeCandidate`, `defaultRouteCandidates`, `pickDefaultRouteCandidate`).
- `internal/netiface/route_darwin_test.go` — unit tests for the pure helpers; uses fabricated `route.RouteMessage` values.
- `internal/scanner/arp_seed_darwin.go` — kernel-ARP-cache reader on macOS via sysctl `NET_RT_FLAGS` + `RTF_LLINFO`. Contains the syscall wrapper, the `extractARPRows` parser, and `rowsToUpdates`.
- `internal/scanner/arp_seed_darwin_test.go` — unit tests for `extractARPRows` and `rowsToUpdates`.

**Modified files:**
- `internal/netiface/route_other.go` — build tag tightens from `!linux && !windows` to `!linux && !windows && !darwin`. Body unchanged.
- `internal/scanner/arp_seed_other.go` — build tag tightens from `!linux && !windows` to `!linux && !windows && !darwin`. Body unchanged.
- `internal/probe/ping_other.go` — one-line change inside `Ping`: `SetPrivileged(runtime.GOOS == "linux")` instead of `SetPrivileged(true)`. Adds `runtime` import.
- `cmd/lan-inventory/main.go` — add a `case "darwin":` branch to the existing `runtime.GOOS` switch in the precheck-failure block.
- `.github/workflows/ci.yml` — append `macos-latest` to the matrix.
- `README.md` — add a macOS install section; update the platform-support Limitations bullet.
- `go.mod` — promote `golang.org/x/net` from indirect to direct dep (already present transitively at v0.49.0).

---

## Task 1: Promote `golang.org/x/net` to a direct dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum` (auto-updated by `go mod tidy`)

`golang.org/x/net/route` is the canonical pure-Go BSD route-message parser. It is already a transitive dep at v0.49.0, but Tasks 2 and 3 import it directly, so it must be declared as a direct dep.

- [ ] **Step 1: Add a no-op import of `golang.org/x/net/route` somewhere temporary to trigger `go mod tidy`'s promotion logic — OR run `go get golang.org/x/net/route` directly.**

Run:

```
go get golang.org/x/net/route
go mod tidy
```

Expected: `go.mod` now lists `golang.org/x/net v0.49.0` in the **first** `require` block (direct deps), no longer in the `// indirect` block.

- [ ] **Step 2: Verify the build still passes on the current platform.**

Run:

```
go build ./...
```

Expected: no output (success).

- [ ] **Step 3: Commit.**

```
git add go.mod go.sum
git commit -m "build: promote golang.org/x/net to a direct dep

Tasks 2 and 3 (Darwin route + ARP seed) import golang.org/x/net/route
directly; declare the dependency accordingly."
```

---

## Task 2: Implement Darwin default-route detection

**Files:**
- Create: `internal/netiface/route_darwin.go`
- Create: `internal/netiface/route_darwin_test.go`
- Modify: `internal/netiface/route_other.go`

This task adds the macOS implementation of `defaultRouteInterface` and tightens `route_other.go`'s build tag in the same commit so the tree stays buildable on every platform at every commit.

- [ ] **Step 1: Write the test file with fabricated `route.RouteMessage` values.**

Create `internal/netiface/route_darwin_test.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build darwin

package netiface

import (
	"net"
	"testing"

	"golang.org/x/net/route"
)

func TestDefaultRouteCandidates_ExtractsDefault(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 4,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},     // dst
				&route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}}, // gateway
				&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},     // netmask
			},
		},
	}
	got := defaultRouteCandidates(msgs)
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
	if got[0].IfaceIndex != 4 {
		t.Errorf("IfaceIndex = %d, want 4", got[0].IfaceIndex)
	}
	if !got[0].Gateway.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("Gateway = %v, want 192.168.1.1", got[0].Gateway)
	}
}

func TestDefaultRouteCandidates_FiltersNonDefault(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 4,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{10, 0, 0, 0}}, // dst non-zero
				&route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}},
				&route.Inet4Addr{IP: [4]byte{255, 0, 0, 0}},
			},
		},
	}
	if got := defaultRouteCandidates(msgs); len(got) != 0 {
		t.Errorf("non-default route should be filtered, got %d candidates", len(got))
	}
}

func TestDefaultRouteCandidates_NetmaskAbsentTreatedAsDefault(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 5,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},
				&route.Inet4Addr{IP: [4]byte{10, 0, 0, 1}},
				// netmask omitted entirely
			},
		},
	}
	if got := defaultRouteCandidates(msgs); len(got) != 1 {
		t.Errorf("absent netmask should count as default, got %d candidates", len(got))
	}
}

func TestDefaultRouteCandidates_NonZeroNetmaskFiltered(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 4,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{0, 0, 0, 0}},
				&route.Inet4Addr{IP: [4]byte{192, 168, 1, 1}},
				&route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}}, // /24, not default
			},
		},
	}
	if got := defaultRouteCandidates(msgs); len(got) != 0 {
		t.Errorf("non-zero netmask should be filtered, got %d candidates", len(got))
	}
}

func TestDefaultRouteCandidates_IPv6Filtered(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 6,
			Addrs: []route.Addr{
				&route.Inet6Addr{IP: [16]byte{}},
				&route.Inet6Addr{IP: [16]byte{}},
			},
		},
	}
	if got := defaultRouteCandidates(msgs); len(got) != 0 {
		t.Errorf("IPv6 route should be filtered, got %d candidates", len(got))
	}
}

func TestPickDefaultRouteCandidate_FirstWins(t *testing.T) {
	cands := []routeCandidate{
		{IfaceIndex: 5, Gateway: net.IPv4(192, 168, 1, 1)},
		{IfaceIndex: 7, Gateway: net.IPv4(10, 0, 0, 1)},
	}
	best, err := pickDefaultRouteCandidate(cands)
	if err != nil {
		t.Fatalf("pickDefaultRouteCandidate: %v", err)
	}
	if best.IfaceIndex != 5 {
		t.Errorf("IfaceIndex = %d, want 5 (first wins)", best.IfaceIndex)
	}
}

func TestPickDefaultRouteCandidate_EmptyReturnsError(t *testing.T) {
	if _, err := pickDefaultRouteCandidate(nil); err == nil {
		t.Errorf("expected error on empty candidate list")
	}
}
```

- [ ] **Step 2: Create the implementation file.**

Create `internal/netiface/route_darwin.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build darwin

// Package netiface — Darwin route resolver. Dumps the IPv4 routing
// table via sysctl (NET_RT_DUMP) and parses it with
// golang.org/x/net/route. The default route is the entry whose
// destination is the IPv4 unspecified address (0.0.0.0) with a missing
// or all-zero netmask.
package netiface

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/route"
)

// BSD RTAX_* indices into route.RouteMessage.Addrs.
const (
	rtaxDst     = 0
	rtaxGateway = 1
	rtaxNetmask = 2
)

// routeCandidate is one default-route entry extracted from a parsed
// route message. Kept as a thin struct so pickDefaultRouteCandidate is
// pure and unit-testable without making real syscalls.
type routeCandidate struct {
	IfaceIndex int
	Gateway    net.IP
}

// defaultRouteInterface dumps the IPv4 routing table via sysctl and
// returns the interface + gateway for the system's default route.
func defaultRouteInterface() (*net.Interface, net.IP, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("FetchRIB(NET_RT_DUMP): %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, nil, fmt.Errorf("ParseRIB(NET_RT_DUMP): %w", err)
	}
	cands := defaultRouteCandidates(msgs)
	best, err := pickDefaultRouteCandidate(cands)
	if err != nil {
		return nil, nil, err
	}
	iface, err := net.InterfaceByIndex(best.IfaceIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("InterfaceByIndex(%d): %w", best.IfaceIndex, err)
	}
	return iface, best.Gateway, nil
}

// defaultRouteCandidates extracts default-route entries from parsed
// route messages. A default route has destination 0.0.0.0 and either a
// missing netmask or an all-zero netmask.
func defaultRouteCandidates(msgs []route.Message) []routeCandidate {
	var cands []routeCandidate
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		if len(rm.Addrs) <= rtaxGateway {
			continue
		}
		dst, ok := rm.Addrs[rtaxDst].(*route.Inet4Addr)
		if !ok {
			continue
		}
		if dst.IP != ([4]byte{0, 0, 0, 0}) {
			continue
		}
		// Netmask absent or all-zero ⇒ default route.
		if len(rm.Addrs) > rtaxNetmask {
			if mask, ok := rm.Addrs[rtaxNetmask].(*route.Inet4Addr); ok {
				if mask.IP != ([4]byte{0, 0, 0, 0}) {
					continue
				}
			}
		}
		gw, ok := rm.Addrs[rtaxGateway].(*route.Inet4Addr)
		if !ok {
			continue
		}
		cands = append(cands, routeCandidate{
			IfaceIndex: rm.Index,
			Gateway:    net.IPv4(gw.IP[0], gw.IP[1], gw.IP[2], gw.IP[3]),
		})
	}
	return cands
}

// pickDefaultRouteCandidate picks the first candidate, which is the
// kernel's preferred default route (matches `netstat -rn` ordering on
// macOS).
func pickDefaultRouteCandidate(cands []routeCandidate) (*routeCandidate, error) {
	if len(cands) == 0 {
		return nil, errors.New("no default route — cannot determine which subnet to scan")
	}
	return &cands[0], nil
}
```

- [ ] **Step 3: Tighten the build tag on `route_other.go`.**

Modify `internal/netiface/route_other.go`. Change the build constraint on line 3 from:

```go
//go:build !linux && !windows
```

to:

```go
//go:build !linux && !windows && !darwin
```

The body is unchanged.

- [ ] **Step 4: Cross-compile to darwin to confirm no symbol collisions and the file builds.**

Run on Windows dev:

```
$env:GOOS = "darwin"; go vet ./internal/netiface/...; $env:GOOS = ""
```

(Bash equivalent: `GOOS=darwin go vet ./internal/netiface/...`)

Expected: no output, exit 0. If you see "defaultRouteInterface redeclared in this package", the `route_other.go` tag tightening in Step 3 did not take effect — re-check the build constraint line.

- [ ] **Step 5: Verify Linux and Windows builds still pass.**

Run:

```
go vet ./internal/netiface/...
$env:GOOS = "linux"; go vet ./internal/netiface/...; $env:GOOS = ""
```

Expected: both succeed silently.

- [ ] **Step 6: Commit.**

```
git add internal/netiface/route_darwin.go internal/netiface/route_darwin_test.go internal/netiface/route_other.go
git commit -m "netiface: detect default route on macOS

Use golang.org/x/net/route to parse the BSD route socket dump and
pick the entry with destination 0.0.0.0 and a missing or all-zero
netmask. The pure helper layer (defaultRouteCandidates,
pickDefaultRouteCandidate) is unit-tested with fabricated
RouteMessage values. _other.go now covers only the remaining BSDs."
```

---

## Task 3: Implement Darwin kernel-ARP-cache seed

**Files:**
- Create: `internal/scanner/arp_seed_darwin.go`
- Create: `internal/scanner/arp_seed_darwin_test.go`
- Modify: `internal/scanner/arp_seed_other.go`

Same pattern as Task 2: add the macOS implementation and tighten the `_other.go` build tag in the same commit.

- [ ] **Step 1: Write the test file.**

Create `internal/scanner/arp_seed_darwin_test.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build darwin

package scanner

import (
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/route"
)

func mustCIDRDarwin(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad CIDR %q: %v", s, err)
	}
	return n
}

func TestRowsToUpdates_BasicHappyPath(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}},
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), now)
	if len(got) != 2 {
		t.Fatalf("want 2 updates, got %d", len(got))
	}
	for _, u := range got {
		if u.Source != "arp-seed" {
			t.Errorf("Source = %q, want arp-seed", u.Source)
		}
		if !u.Time.Equal(now) {
			t.Errorf("Time = %v, want %v", u.Time, now)
		}
		if u.MAC != strings.ToLower(u.MAC) {
			t.Errorf("MAC %q not lowercase", u.MAC)
		}
	}
	if got[0].MAC != "08:3a:8d:8e:3e:f0" {
		t.Errorf("row 0 MAC mismatch: %q", got[0].MAC)
	}
}

func TestRowsToUpdates_FiltersWrongIface(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}},
		{IfaceIndex: 9, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 10)) {
		t.Fatalf("iface filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersOutsideSubnet(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}},
		{IfaceIndex: 7, IP: net.IPv4(10, 0, 0, 5), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 10)) {
		t.Fatalf("subnet filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersZeroMAC(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0, 0, 0, 0, 0, 0}},
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 11)) {
		t.Fatalf("zero-MAC filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersShortMAC(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d}}, // 3 bytes
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 11)) {
		t.Fatalf("short-MAC filter failed: %+v", got)
	}
}

func TestRowsToUpdates_PopulatesVendor(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}},
	}
	got := rowsToUpdates(rows, 7, mustCIDRDarwin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 {
		t.Fatalf("want 1 update, got %d", len(got))
	}
	if got[0].Vendor == "" {
		t.Error("expected non-empty Vendor for known OUI 08:3a:8d")
	}
}

func TestExtractARPRows_ParsesValidEntry(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 4,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{192, 168, 1, 10}},
				&route.LinkAddr{Index: 4, Addr: []byte{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}},
			},
		},
	}
	rows := extractARPRows(msgs)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].IfaceIndex != 4 {
		t.Errorf("IfaceIndex = %d, want 4", rows[0].IfaceIndex)
	}
	if !rows[0].IP.Equal(net.IPv4(192, 168, 1, 10)) {
		t.Errorf("IP = %v, want 192.168.1.10", rows[0].IP)
	}
	if rows[0].MAC.String() != "08:3a:8d:8e:3e:f0" {
		t.Errorf("MAC = %v", rows[0].MAC)
	}
}

func TestExtractARPRows_FiltersShortLinkAddr(t *testing.T) {
	msgs := []route.Message{
		&route.RouteMessage{
			Index: 4,
			Addrs: []route.Addr{
				&route.Inet4Addr{IP: [4]byte{192, 168, 1, 10}},
				&route.LinkAddr{Index: 4, Addr: []byte{0x08}}, // 1 byte ⇒ filtered
			},
		},
	}
	if rows := extractARPRows(msgs); len(rows) != 0 {
		t.Errorf("expected short-MAC LinkAddr filtered, got %d rows", len(rows))
	}
}

func TestExtractARPRows_FiltersNonRouteMessage(t *testing.T) {
	// A message that is not a *route.RouteMessage (e.g. interface
	// message) should be skipped.
	msgs := []route.Message{
		&route.InterfaceMessage{Index: 4},
	}
	if rows := extractARPRows(msgs); len(rows) != 0 {
		t.Errorf("expected non-RouteMessage filtered, got %d rows", len(rows))
	}
}
```

- [ ] **Step 2: Create the implementation file.**

Create `internal/scanner/arp_seed_darwin.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build darwin

package scanner

import (
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/route"

	"github.com/lab1702/lan-inventory/internal/oui"
)

// BSD sysctl + route-flag constants. Values match
// golang.org/x/sys/unix.{NET_RT_FLAGS,RTF_LLINFO} on darwin; held as
// private literals here to avoid pulling x/sys/unix just for two
// integers.
const (
	netRTFlags = 2
	rtfLLINFO  = 0x400
)

// arpRow is the platform-agnostic projection of a BSD ARP-cache entry.
// rowsToUpdates operates on this so unit tests do not need to make
// syscalls.
type arpRow struct {
	IfaceIndex int
	IP         net.IP
	MAC        net.HardwareAddr
}

// rowsToUpdates filters arpRows by interface index and subnet
// membership, drops zero-length / all-zero MACs, and emits one Update
// per survivor. Shape matches parseProcNetARP and the Windows
// rowsToUpdates exactly: Source "arp-seed", lowercase MAC, vendor
// populated from the bundled OUI table.
func rowsToUpdates(rows []arpRow, ifaceIndex int, subnet *net.IPNet, now time.Time) []Update {
	var out []Update
	for _, r := range rows {
		if r.IfaceIndex != ifaceIndex {
			continue
		}
		if len(r.MAC) != 6 {
			continue
		}
		if isZeroMAC(r.MAC) {
			continue
		}
		ip4 := r.IP.To4()
		if ip4 == nil || !subnet.Contains(ip4) {
			continue
		}
		mac := strings.ToLower(r.MAC.String())
		out = append(out, Update{
			Source: "arp-seed",
			Time:   now,
			MAC:    mac,
			IP:     ip4,
			Vendor: oui.Lookup(mac),
		})
	}
	return out
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

// extractARPRows pulls per-neighbor entries out of parsed route
// messages. ARP-cache entries arrive as *route.RouteMessage with
// Addrs[0] = neighbor IPv4 address and Addrs[1] = LinkAddr carrying
// the MAC.
func extractARPRows(msgs []route.Message) []arpRow {
	var out []arpRow
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		if len(rm.Addrs) < 2 {
			continue
		}
		dst, ok := rm.Addrs[0].(*route.Inet4Addr)
		if !ok {
			continue
		}
		la, ok := rm.Addrs[1].(*route.LinkAddr)
		if !ok {
			continue
		}
		if len(la.Addr) != 6 {
			continue
		}
		out = append(out, arpRow{
			IfaceIndex: rm.Index,
			IP:         net.IPv4(dst.IP[0], dst.IP[1], dst.IP[2], dst.IP[3]),
			MAC:        net.HardwareAddr(la.Addr),
		})
	}
	return out
}

// SeedFromKernelARP reads the IPv4 ARP cache via
// sysctl(NET_RT_FLAGS, RTF_LLINFO) and emits one Update per neighbor
// on the chosen interface within subnet. Best-effort: returns nil on
// any failure.
func SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update {
	if ifaceName == "" || subnet == nil {
		return nil
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}
	rib, err := route.FetchRIB(syscall.AF_INET, route.RIBType(netRTFlags), rtfLLINFO)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	return rowsToUpdates(extractARPRows(msgs), iface.Index, subnet, time.Now())
}
```

- [ ] **Step 3: Tighten the build tag on `arp_seed_other.go`.**

Modify `internal/scanner/arp_seed_other.go`. Change the build constraint on line 3 from:

```go
//go:build !linux && !windows
```

to:

```go
//go:build !linux && !windows && !darwin
```

The body is unchanged. Update the doc comment to reflect that macOS now has a real implementation:

Change line 9 from:

```go
// SeedFromKernelARP is a no-op on macOS/BSD platforms. /proc/net/arp is
// Linux-specific; macOS/BSD use sysctl(NET_RT_FLAGS) which is not wired
// up. ARPWorker still functions (libpcap is cross-platform), so users
// only lose the startup shortcut, not correctness.
```

to:

```go
// SeedFromKernelARP is a no-op on *BSD platforms (FreeBSD, OpenBSD,
// NetBSD). Linux uses /proc/net/arp; Windows and macOS use
// platform-specific implementations. *BSD startup hard-fails earlier
// in route detection anyway, so this no-op is dead code in practice
// but kept for build-tag symmetry.
```

- [ ] **Step 4: Cross-compile to darwin to confirm symbols resolve.**

Run on Windows dev:

```
$env:GOOS = "darwin"; go vet ./internal/scanner/...; $env:GOOS = ""
```

Expected: no output, exit 0. If you see "SeedFromKernelARP redeclared in this package", the build constraint on `arp_seed_other.go` did not take effect — re-check Step 3.

- [ ] **Step 5: Verify Linux and Windows builds still pass.**

Run:

```
go vet ./internal/scanner/...
$env:GOOS = "linux"; go vet ./internal/scanner/...; $env:GOOS = ""
```

Expected: both succeed silently.

- [ ] **Step 6: Commit.**

```
git add internal/scanner/arp_seed_darwin.go internal/scanner/arp_seed_darwin_test.go internal/scanner/arp_seed_other.go
git commit -m "scanner: seed kernel ARP cache on macOS

Read the IPv4 ARP cache via sysctl(NET_RT_FLAGS, RTF_LLINFO) and
parse with golang.org/x/net/route. The pure helpers extractARPRows
and rowsToUpdates are unit-tested with fabricated route messages.
_other.go now covers only the remaining BSDs."
```

---

## Task 4: Make ICMP unprivileged on macOS

**Files:**
- Modify: `internal/probe/ping_other.go`

Change the `SetPrivileged` rule from "everywhere except Windows" to "Linux only". macOS allows `SOCK_DGRAM` ICMP for any user; running unprivileged means ChmodBPF (or sudo) is only needed for pcap, not ICMP.

- [ ] **Step 1: Update the `SetPrivileged` line and add the `runtime` import.**

Modify `internal/probe/ping_other.go`. The file currently is:

```go
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build !windows

package probe

import (
	"context"
	"fmt"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)
```

Add `"runtime"` to the import block so the imports become:

```go
import (
	"context"
	"fmt"
	"runtime"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)
```

Then change the line `pinger.SetPrivileged(true)` to:

```go
pinger.SetPrivileged(runtime.GOOS == "linux")
```

No other changes.

- [ ] **Step 2: Verify the file compiles on each platform.**

Run:

```
go vet ./internal/probe/...
$env:GOOS = "darwin"; go vet ./internal/probe/...; $env:GOOS = ""
$env:GOOS = "linux"; go vet ./internal/probe/...; $env:GOOS = ""
```

Expected: all three succeed silently.

- [ ] **Step 3: Run the existing ping tests on the current platform to confirm no regression.**

Run:

```
go test ./internal/probe/...
```

Expected: all tests pass. On Windows the ping tests already use the dedicated `ping_windows.go` (untouched), so behavior is unchanged.

- [ ] **Step 4: Commit.**

```
git add internal/probe/ping_other.go
git commit -m "probe: use unprivileged ICMP on macOS

macOS allows SOCK_DGRAM ICMP for any user, so the ping probe no
longer requires sudo on Darwin. Linux still uses the privileged
raw-socket mode (caller is expected to setcap or sudo)."
```

---

## Task 5: Add a darwin precheck-failure hint to main.go

**Files:**
- Modify: `cmd/lan-inventory/main.go`

The precheck-failure block in `main()` already switches on `runtime.GOOS`. Add a `darwin` case.

- [ ] **Step 1: Insert the new switch case.**

Modify `cmd/lan-inventory/main.go`. Find the block (currently around line 53–64):

```go
		switch runtime.GOOS {
		case "linux":
			fmt.Fprintln(os.Stderr, "Either run with sudo, or grant capabilities once:")
			fmt.Fprintln(os.Stderr, "    sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-inventory)")
		case "windows":
			fmt.Fprintln(os.Stderr, "Install Npcap from https://npcap.com/")
			fmt.Fprintln(os.Stderr, `(check "WinPcap API-compatible mode" during install).`)
			fmt.Fprintln(os.Stderr, "The driver grants user-level capture; no per-run Administrator needed.")
		default:
			fmt.Fprintln(os.Stderr, "This platform may need additional privileges to open packet capture.")
			fmt.Fprintln(os.Stderr, "Consult your OS docs for how to grant raw-socket / pcap access.")
		}
```

Insert a `darwin` case between `windows` and `default`. The block becomes:

```go
		switch runtime.GOOS {
		case "linux":
			fmt.Fprintln(os.Stderr, "Either run with sudo, or grant capabilities once:")
			fmt.Fprintln(os.Stderr, "    sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-inventory)")
		case "windows":
			fmt.Fprintln(os.Stderr, "Install Npcap from https://npcap.com/")
			fmt.Fprintln(os.Stderr, `(check "WinPcap API-compatible mode" during install).`)
			fmt.Fprintln(os.Stderr, "The driver grants user-level capture; no per-run Administrator needed.")
		case "darwin":
			fmt.Fprintln(os.Stderr, "Either install Wireshark's ChmodBPF helper")
			fmt.Fprintln(os.Stderr, "(brew install --cask wireshark), or run with sudo:")
			fmt.Fprintln(os.Stderr, "    sudo lan-inventory")
		default:
			fmt.Fprintln(os.Stderr, "This platform may need additional privileges to open packet capture.")
			fmt.Fprintln(os.Stderr, "Consult your OS docs for how to grant raw-socket / pcap access.")
		}
```

- [ ] **Step 2: Verify the build still passes on each platform.**

Run:

```
go vet ./...
$env:GOOS = "darwin"; go vet ./...; $env:GOOS = ""
$env:GOOS = "linux"; go vet ./...; $env:GOOS = ""
```

Expected: all three succeed silently.

- [ ] **Step 3: Commit.**

```
git add cmd/lan-inventory/main.go
git commit -m "main: add macOS precheck-failure hint

Point macOS users at ChmodBPF (preferred) or sudo when pcap fails."
```

---

## Task 6: Add macos-latest to the CI matrix

**Files:**
- Modify: `.github/workflows/ci.yml`

libpcap ships with macOS, so no extra install step is needed. The existing Linux- and Windows-only steps already have `runner.os` guards.

- [ ] **Step 1: Append `macos-latest` to the matrix.**

Modify `.github/workflows/ci.yml`. Change line 13 from:

```yaml
        os: [ubuntu-latest, windows-latest]
```

to:

```yaml
        os: [ubuntu-latest, windows-latest, macos-latest]
```

No other changes are needed — the `if: runner.os == 'Linux'` and `if: runner.os == 'Windows'` guards on the existing platform-specific steps automatically skip them on macOS.

- [ ] **Step 2: Lint the YAML by re-reading it.**

Run:

```
git diff .github/workflows/ci.yml
```

Confirm the diff is a single-line change adding `, macos-latest` to the matrix.

- [ ] **Step 3: Commit.**

```
git add .github/workflows/ci.yml
git commit -m "ci: add macos-latest to the test matrix

libpcap ships with macOS, so no install step is needed. Existing
runner.os guards on the Linux/Windows steps skip them on macOS."
```

---

## Task 7: Update README

**Files:**
- Modify: `README.md`

Two changes: add a macOS install section, and update the Limitations bullet about platform support.

- [ ] **Step 1: Add the macOS install section.**

Modify `README.md`. Find the `### Windows` section (currently around line 39–53). After the closing of that section and before the `## Usage` heading (currently line 55), insert a new `### macOS` section.

The new content to insert (the outer ```` ``` ```` fences below are part of this plan; the **inner** triple-backtick fences are what actually goes into the README):

````markdown
### macOS

The recommended path uses Wireshark's ChmodBPF launchd helper to grant
non-root access to `/dev/bpf*`, mirroring the Linux `setcap` UX:

```bash
brew install --cask wireshark
go install github.com/lab1702/lan-inventory/cmd/lan-inventory@latest
lan-inventory
```

Or, without Wireshark, run per-invocation as root:

```bash
go install github.com/lab1702/lan-inventory/cmd/lan-inventory@latest
sudo lan-inventory
```

libpcap ships with macOS — no extra install step is needed. ICMP uses
unprivileged `SOCK_DGRAM` sockets, so the only privilege gate is BPF
read access.
````

- [ ] **Step 2: Update the Limitations bullet about platform support.**

Find the Limitations bullet (currently line 87–89):

```markdown
- Supported on Linux and Windows. macOS and *BSD builds compile but fail
  at startup (default-route detection is not implemented for those
  platforms).
```

Replace with:

```markdown
- Supported on Linux, macOS, and Windows. *BSD builds compile but fail
  at startup (default-route detection is not implemented for those
  platforms).
```

- [ ] **Step 3: Verify the rendered Markdown looks right.**

Open `README.md` in a previewer (or VS Code's Markdown preview) and confirm:
- The new `### macOS` section appears between `### Windows` and `## Usage`.
- Both code blocks inside it render with proper monospace.
- The Limitations bullet reads cleanly.

- [ ] **Step 4: Commit.**

```
git add README.md
git commit -m "docs: add macOS install instructions; drop macOS limitation

ChmodBPF (preferred) or sudo (fallback). libpcap ships with macOS;
ICMP uses unprivileged SOCK_DGRAM."
```

---

## Task 8: Final verification

This task has no code changes — it's a checklist for end-to-end confidence before merging.

- [ ] **Step 1: Cross-compile on Windows for all three platforms.**

```
go vet ./...
$env:GOOS = "linux"; go vet ./...; $env:GOOS = ""
$env:GOOS = "darwin"; go vet ./...; $env:GOOS = ""
```

Expected: all three succeed silently.

- [ ] **Step 2: Run the current-platform test suite.**

```
go test ./...
```

Expected: all tests pass on Windows. Darwin-tagged tests are skipped (their files are excluded from the build set on non-darwin).

- [ ] **Step 3: Push and confirm CI passes on all three runners.**

```
git push
```

Watch the CI page. All three matrix legs (`ubuntu-latest`, `windows-latest`, `macos-latest`) must pass `go vet`, `staticcheck`, and `go test ./...` before merging.

- [ ] **Step 4 (manual, requires a Mac): Smoke test on macOS.**

If a Mac is available:

1. Install Wireshark via `brew install --cask wireshark` (this installs ChmodBPF). Or skip this and use `sudo` in step 3.
2. `git pull` the branch on the Mac.
3. `go build ./cmd/lan-inventory`
4. From a **non-root** terminal (or `sudo` if Wireshark was skipped):
   - `./lan-inventory --version` — prints version.
   - `./lan-inventory --once --table` — prints device rows with IPs, MACs, vendors, hostnames.
   - `./lan-inventory` — TUI opens; tabs 1–4 work; `/` filter, `↑/↓`, `r` rescan, `q` quit all work.
5. Confirm the snapshot includes MAC + vendor for hosts that stealth-drop ICMP (validates ARP seed populating from the kernel cache).
6. Confirm at least one Linux host on the LAN shows `os ~ linux/unix` and one Windows host shows `os ~ windows` (validates TTL propagation through unprivileged ICMP).

If no Mac is available, CI plus careful review must suffice; the manual smoke test can happen post-merge before the next release tag.

---

## Verification summary

After all tasks:

- `go.mod` lists `golang.org/x/net` as a direct dep.
- `internal/netiface/route_darwin.go` and `internal/netiface/route_darwin_test.go` exist; `route_other.go`'s tag is `!linux && !windows && !darwin`.
- `internal/scanner/arp_seed_darwin.go` and `internal/scanner/arp_seed_darwin_test.go` exist; `arp_seed_other.go`'s tag is `!linux && !windows && !darwin`.
- `internal/probe/ping_other.go` uses `SetPrivileged(runtime.GOOS == "linux")`.
- `cmd/lan-inventory/main.go` has a `case "darwin":` in the precheck-failure switch.
- `.github/workflows/ci.yml` includes `macos-latest`.
- `README.md` has a `### macOS` install section; Limitations no longer says macOS is unsupported.
- CI is green on all three platforms.
