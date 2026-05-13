# Windows parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Windows build of `lan-inventory` to full feature parity with the Linux build (passive ARP sniffing, kernel ARP seed, default-route detection, active probes, mDNS, TUI).

**Architecture:** Two new build-tagged Go files mirror the existing Linux split: `netiface/route_windows.go` and `scanner/arp_seed_windows.go`. The Windows route resolver picks the operational adapter with the lowest IPv4 metric via `GetAdaptersAddresses`. The Windows ARP-cache seed reads the kernel neighbor table via raw `iphlpapi.GetIpNetTable2` syscall. Tests cover pure data-shaping helpers; syscall wrappers are integration-tested via the manual smoke test. `probe/ping.go` switches to `pro-bing`'s unprivileged mode on Windows (using `IcmpSendEcho`, no Administrator). Packet capture relies on Npcap (cross-platform `gopacket/pcap`). CI gains a `windows-latest` matrix job that installs the Npcap SDK headers.

**Tech Stack:** Go 1.24, `golang.org/x/sys/windows` (direct dep), `gopacket/pcap` + Npcap, `pro-bing`, GitHub Actions matrix CI.

**Spec:** `docs/superpowers/specs/2026-05-13-windows-parity-design.md`

---

## Task 1: Baseline build sanity check

**Files:** none modified.

Confirm the current `main` branch builds and tests cleanly on the implementer's host before starting work, so any breakage later is clearly caused by this plan.

- [ ] **Step 1: Verify go.mod and clean build**

```bash
go mod tidy
go build ./...
go test ./...
```

Expected: clean. No commit. (`golang.org/x/sys/windows` will be auto-promoted to a direct dep when Task 5 first imports it; no preemptive plumbing required.)

---

## Task 2: Platform-aware ICMP privilege in `probe/ping.go`

**Files:**
- Modify: `internal/probe/ping.go`
- Modify: `internal/probe/ping_test.go`

Switch `pro-bing` to unprivileged mode on Windows (uses `IcmpSendEcho`, returns TTL, needs no admin). Linux behavior unchanged.

- [ ] **Step 1: Write the failing test**

Append to `internal/probe/ping_test.go`:

```go
func TestDefaultPrivileged(t *testing.T) {
	want := runtime.GOOS != "windows"
	if got := probe.DefaultPrivileged(); got != want {
		t.Errorf("DefaultPrivileged() = %v, want %v (GOOS=%s)", got, want, runtime.GOOS)
	}
}
```

Add `"runtime"` to the import block.

- [ ] **Step 2: Run the test, confirm it fails**

```bash
go test ./internal/probe/ -run TestDefaultPrivileged -v
```

Expected: FAIL — `probe.DefaultPrivileged` undefined.

- [ ] **Step 3: Add `DefaultPrivileged` and use it in `Ping`**

Edit `internal/probe/ping.go`. Add the import `"runtime"` to the existing import block, and add this function:

```go
// DefaultPrivileged reports whether pro-bing should run in privileged
// (raw-socket) mode on the current platform. Linux and other Unixes
// require raw sockets for ICMP echo; Windows can use the unprivileged
// IcmpSendEcho Win32 API and still report TTL/RTT.
func DefaultPrivileged() bool {
	return runtime.GOOS != "windows"
}
```

Replace this line in `Ping`:

```go
	pinger.SetPrivileged(true)
```

with:

```go
	pinger.SetPrivileged(DefaultPrivileged())
```

- [ ] **Step 4: Run the test, confirm it passes**

```bash
go test ./internal/probe/ -run TestDefaultPrivileged -v
```

Expected: PASS.

- [ ] **Step 5: Run the full probe package tests**

```bash
go test ./internal/probe/ -v
```

Expected: all PASS or SKIP (existing tests skip on raw-socket failure).

- [ ] **Step 6: Commit**

```bash
git add internal/probe/ping.go internal/probe/ping_test.go
git commit -m "probe: use unprivileged ICMP path on Windows

pro-bing in unprivileged mode calls IcmpSendEcho (iphlpapi) on Windows,
which still reports TTL and RTT and does not require Administrator. Other
platforms keep the existing raw-socket path."
```

---

## Task 3: Tighten build tag on `netiface/route_other.go`

**Files:**
- Modify: `internal/netiface/route_other.go`

Make room for the new Windows file.

- [ ] **Step 1: Change the build tag**

Replace the existing build tag line:

```go
//go:build !linux
```

with:

```go
//go:build !linux && !windows
```

The rest of the file is unchanged.

- [ ] **Step 2: Verify the package still builds**

```bash
go build ./internal/netiface/
```

Expected: builds cleanly (the file is dormant on linux/windows builds, active on macOS/BSD).

- [ ] **Step 3: Commit**

```bash
git add internal/netiface/route_other.go
git commit -m "netiface: tighten route_other.go build tag to non-linux non-windows

Prepares for route_windows.go in the next commit."
```

---

## Task 4: `netiface/route_windows.go` — pure helper + test

**Files:**
- Create: `internal/netiface/route_windows.go`
- Create: `internal/netiface/route_windows_test.go`

The Win32 syscall layer cannot be unit-tested, but the candidate-selection logic can. This task creates only the pure helper. Task 5 adds the syscall wrapper.

- [ ] **Step 1: Write the failing test**

Create `internal/netiface/route_windows_test.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package netiface

import (
	"net"
	"testing"
)

func TestPickBestGatewayCandidate_LowestMetricWins(t *testing.T) {
	cands := []gatewayCandidate{
		{IfaceIndex: 5, Gateway: net.IPv4(192, 168, 1, 1), Metric: 25},
		{IfaceIndex: 7, Gateway: net.IPv4(10, 0, 0, 1), Metric: 15},
		{IfaceIndex: 9, Gateway: net.IPv4(172, 16, 0, 1), Metric: 40},
	}
	best, err := pickBestGatewayCandidate(cands)
	if err != nil {
		t.Fatalf("pickBestGatewayCandidate: %v", err)
	}
	if best.IfaceIndex != 7 {
		t.Errorf("IfaceIndex = %d, want 7", best.IfaceIndex)
	}
	if !best.Gateway.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Errorf("Gateway = %v, want 10.0.0.1", best.Gateway)
	}
}

func TestPickBestGatewayCandidate_EmptyReturnsError(t *testing.T) {
	if _, err := pickBestGatewayCandidate(nil); err == nil {
		t.Errorf("expected error on empty candidate list")
	}
}

func TestPickBestGatewayCandidate_StableOnTies(t *testing.T) {
	// Equal metric — the first candidate wins (deterministic).
	cands := []gatewayCandidate{
		{IfaceIndex: 3, Gateway: net.IPv4(192, 168, 1, 1), Metric: 20},
		{IfaceIndex: 4, Gateway: net.IPv4(10, 0, 0, 1), Metric: 20},
	}
	best, err := pickBestGatewayCandidate(cands)
	if err != nil {
		t.Fatalf("pickBestGatewayCandidate: %v", err)
	}
	if best.IfaceIndex != 3 {
		t.Errorf("IfaceIndex = %d, want 3 (first wins on tie)", best.IfaceIndex)
	}
}
```

- [ ] **Step 2: Run the test, confirm it fails to compile**

```bash
go test -tags=windows ./internal/netiface/ -run TestPickBestGatewayCandidate -v
```

On a non-Windows host the `windows` build tag prevents this test from compiling — that's expected; the real run happens on the Windows CI job. If you are on Windows:

```powershell
go test ./internal/netiface/ -run TestPickBestGatewayCandidate -v
```

Expected: FAIL — `pickBestGatewayCandidate` undefined.

- [ ] **Step 3: Create the route_windows.go file with the pure helper**

Create `internal/netiface/route_windows.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

// Package netiface — Windows route resolver. We pick the operational
// adapter with the lowest IPv4 metric whose adapter advertises a
// non-empty gateway list. That matches the Linux semantics of "default
// route with the lowest metric".
package netiface

import (
	"errors"
	"fmt"
	"net"
)

// gatewayCandidate is one row of the working set used to pick the
// default-route adapter. Extracted so the selection logic is pure and
// unit-testable without making real syscalls.
type gatewayCandidate struct {
	IfaceIndex uint32
	Gateway    net.IP
	Metric     uint32
}

// pickBestGatewayCandidate returns the candidate with the lowest Metric.
// On ties, the first one in the input slice wins.
func pickBestGatewayCandidate(cands []gatewayCandidate) (*gatewayCandidate, error) {
	if len(cands) == 0 {
		return nil, errors.New("no default route — cannot determine which subnet to scan")
	}
	best := &cands[0]
	for i := 1; i < len(cands); i++ {
		if cands[i].Metric < best.Metric {
			best = &cands[i]
		}
	}
	return best, nil
}

// defaultRouteInterface enumerates Windows adapters via GetAdaptersAddresses,
// collects every operational IPv4 adapter that has at least one gateway,
// and returns the one with the lowest Ipv4Metric.
func defaultRouteInterface() (*net.Interface, net.IP, error) {
	cands, err := collectGatewayCandidates()
	if err != nil {
		return nil, nil, err
	}
	best, err := pickBestGatewayCandidate(cands)
	if err != nil {
		return nil, nil, err
	}
	iface, err := net.InterfaceByIndex(int(best.IfaceIndex))
	if err != nil {
		return nil, nil, fmt.Errorf("net.InterfaceByIndex(%d): %w", best.IfaceIndex, err)
	}
	return iface, best.Gateway, nil
}

// collectGatewayCandidates is the syscall-touching half of the resolver.
// Implemented in Task 5.
func collectGatewayCandidates() ([]gatewayCandidate, error) {
	return nil, errors.New("collectGatewayCandidates: not yet implemented")
}
```

- [ ] **Step 4: Run the test, confirm it passes**

On Windows:

```powershell
go test ./internal/netiface/ -run TestPickBestGatewayCandidate -v
```

Expected: all three tests PASS.

On Linux/macOS: skip — the file is `//go:build windows`.

- [ ] **Step 5: Build the full module to confirm cross-platform integrity**

```bash
go build ./...
```

Expected: builds cleanly on Linux (the file is dormant). The `collectGatewayCandidates` stub is unused inside this task — the import of `windows` and the touch of `IpAdapterAddresses` keep the file legal under `go vet`.

- [ ] **Step 6: Commit**

```bash
git add internal/netiface/route_windows.go internal/netiface/route_windows_test.go
git commit -m "netiface: add Windows route resolver scaffold with pure picker

Pure helper pickBestGatewayCandidate selects the gateway with the lowest
Ipv4Metric and is unit-tested. The syscall-touching collectGatewayCandidates
is stubbed; the real implementation lands in the next commit."
```

---

## Task 5: Wire up `collectGatewayCandidates` via `GetAdaptersAddresses`

**Files:**
- Modify: `internal/netiface/route_windows.go`

Replace the stub with a real implementation. No new unit tests — this is syscall-bound and verified by the manual smoke test (Task 12).

- [ ] **Step 1: Add the syscall imports and replace the stub**

In `internal/netiface/route_windows.go`, expand the import block to:

```go
import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)
```

Then replace the `collectGatewayCandidates` function with:

```go
// collectGatewayCandidates calls GetAdaptersAddresses with
// GAA_FLAG_INCLUDE_GATEWAYS and returns one candidate per operational
// adapter that has at least one IPv4 gateway. The adapter's Ipv4Metric is
// captured as Metric so pickBestGatewayCandidate can choose the default
// route.
func collectGatewayCandidates() ([]gatewayCandidate, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS |
		windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST |
		windows.GAA_FLAG_SKIP_DNS_SERVER

	// Probe size, then allocate.
	var bufLen uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, nil, &bufLen)
	if err != windows.ERROR_BUFFER_OVERFLOW {
		return nil, fmt.Errorf("GetAdaptersAddresses (size probe): %w", err)
	}
	buf := make([]byte, bufLen)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &bufLen); err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	var cands []gatewayCandidate
	for aa := first; aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp {
			continue
		}
		gw := firstIPv4Gateway(aa)
		if gw == nil {
			continue
		}
		cands = append(cands, gatewayCandidate{
			IfaceIndex: aa.IfIndex,
			Gateway:    gw,
			Metric:     aa.Ipv4Metric,
		})
	}
	return cands, nil
}

// firstIPv4Gateway returns the first IPv4 address found in the adapter's
// linked list of gateway addresses, or nil if there is none.
func firstIPv4Gateway(aa *windows.IpAdapterAddresses) net.IP {
	for ga := aa.FirstGatewayAddress; ga != nil; ga = ga.Next {
		sa, err := ga.Address.Sockaddr.Sockaddr()
		if err != nil {
			continue
		}
		if sa4, ok := sa.(*windows.SockaddrInet4); ok {
			return net.IPv4(sa4.Addr[0], sa4.Addr[1], sa4.Addr[2], sa4.Addr[3])
		}
	}
	return nil
}
```

- [ ] **Step 2: Promote `golang.org/x/sys` to a direct dep**

```bash
go mod tidy
```

Expected: `go.mod` now lists `golang.org/x/sys` in the first `require` block without `// indirect`. `go.sum` may also update — that's fine.

- [ ] **Step 3: Build to confirm**

```bash
GOOS=windows go build ./internal/netiface/
```

On Windows:

```powershell
go build ./internal/netiface/
```

Expected: clean build. If the call signature of `windows.GetAdaptersAddresses` does not match (its signature has shifted across `x/sys` versions), fix the call site — the type of the buffer pointer argument may need to be `*windows.IpAdapterAddresses` directly. The intent is unchanged.

- [ ] **Step 4: Run the existing tests**

On Windows:

```powershell
go test ./internal/netiface/ -v
```

Expected: pure tests still pass; the syscall path is covered by the smoke test.

- [ ] **Step 5: Commit**

```bash
git add internal/netiface/route_windows.go go.mod go.sum
git commit -m "netiface: implement Windows default-route detection

Use GetAdaptersAddresses with GAA_FLAG_INCLUDE_GATEWAYS to enumerate
operational IPv4 adapters; the one with the lowest Ipv4Metric is the
default-route adapter."
```

---

## Task 6: Tighten build tag on `scanner/arp_seed_other.go`

**Files:**
- Modify: `internal/scanner/arp_seed_other.go`

- [ ] **Step 1: Change the build tag**

Replace:

```go
//go:build !linux
```

with:

```go
//go:build !linux && !windows
```

Also update the package-level comment in the function body — change the second sentence to:

```go
// SeedFromKernelARP is a no-op on macOS/BSD platforms. /proc/net/arp is
// Linux-specific; macOS/BSD use sysctl(NET_RT_FLAGS) which is not wired
// up. ARPWorker still functions (libpcap is cross-platform), so users
// only lose the startup shortcut, not correctness.
```

- [ ] **Step 2: Verify build**

```bash
go build ./internal/scanner/
```

Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add internal/scanner/arp_seed_other.go
git commit -m "scanner: tighten arp_seed_other.go build tag to non-linux non-windows

Prepares for arp_seed_windows.go in the next commit."
```

---

## Task 7: `scanner/arp_seed_windows.go` — pure helper + test

**Files:**
- Create: `internal/scanner/arp_seed_windows.go`
- Create: `internal/scanner/arp_seed_windows_test.go`

Same split as Task 4: this task creates only the pure data-shaping helper. Task 8 wires it to `iphlpapi.GetIpNetTable2`.

- [ ] **Step 1: Write the failing test**

Create `internal/scanner/arp_seed_windows_test.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package scanner

import (
	"net"
	"strings"
	"testing"
	"time"
)

func mustCIDRWin(t *testing.T, s string) *net.IPNet {
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
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}, Reachable: true},
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), now)
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
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}, Reachable: true},
		{IfaceIndex: 9, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 10)) {
		t.Fatalf("iface filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersOutsideSubnet(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}, Reachable: true},
		{IfaceIndex: 7, IP: net.IPv4(10, 0, 0, 5), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 10)) {
		t.Fatalf("subnet filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersUnreachable(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}, Reachable: false},
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 11)) {
		t.Fatalf("reachable filter failed: %+v", got)
	}
}

func TestRowsToUpdates_FiltersZeroMAC(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0, 0, 0, 0, 0, 0}, Reachable: true},
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 11), MAC: net.HardwareAddr{0x02, 0x81, 0x45, 0x19, 0x9e, 0xc6}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 || !got[0].IP.Equal(net.IPv4(192, 168, 0, 11)) {
		t.Fatalf("zero-MAC filter failed: %+v", got)
	}
}

func TestRowsToUpdates_PopulatesVendor(t *testing.T) {
	rows := []arpRow{
		{IfaceIndex: 7, IP: net.IPv4(192, 168, 0, 10), MAC: net.HardwareAddr{0x08, 0x3a, 0x8d, 0x8e, 0x3e, 0xf0}, Reachable: true},
	}
	got := rowsToUpdates(rows, 7, mustCIDRWin(t, "192.168.0.0/24"), time.Now())
	if len(got) != 1 {
		t.Fatalf("want 1 update, got %d", len(got))
	}
	if got[0].Vendor == "" {
		t.Error("expected non-empty Vendor for known OUI 08:3a:8d")
	}
}
```

- [ ] **Step 2: Run the test, confirm it fails to compile**

On Windows:

```powershell
go test ./internal/scanner/ -run TestRowsToUpdates -v
```

Expected: FAIL — `arpRow` and `rowsToUpdates` undefined.

On Linux/macOS the test won't compile due to the build tag — that's correct.

- [ ] **Step 3: Create the `arp_seed_windows.go` file with the helper**

Create `internal/scanner/arp_seed_windows.go`:

```go
// SPDX-License-Identifier: GPL-2.0-or-later

//go:build windows

package scanner

import (
	"net"
	"strings"
	"time"

	"github.com/lab1702/lan-inventory/internal/oui"
)

// arpRow is the platform-agnostic projection of a Win32 ARP-table row.
// The pure rowsToUpdates helper operates on this so unit tests do not
// need to make syscalls.
type arpRow struct {
	IfaceIndex uint32
	IP         net.IP
	MAC        net.HardwareAddr
	// Reachable is true for entries whose Win32 state is one of
	// Reachable / Stale / Delay / Probe — i.e., the kernel has a real
	// MAC for this neighbor. False for Unreachable / Incomplete.
	Reachable bool
}

// rowsToUpdates filters arpRows by interface index and subnet membership,
// drops zero-MAC and unreachable entries, and emits one Update per
// survivor. The emitted shape is identical to parseProcNetARP's output on
// Linux: Source "arp-seed", lowercase MAC, vendor populated from the
// bundled OUI table.
func rowsToUpdates(rows []arpRow, ifaceIndex uint32, subnet *net.IPNet, now time.Time) []Update {
	var out []Update
	for _, r := range rows {
		if r.IfaceIndex != ifaceIndex {
			continue
		}
		if !r.Reachable {
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

// SeedFromKernelARP is the public entry point matching the Linux
// signature. Wired to the iphlpapi syscall in the next commit.
func SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update {
	_ = ifaceName
	_ = subnet
	return nil
}
```

- [ ] **Step 4: Run the test, confirm it passes**

On Windows:

```powershell
go test ./internal/scanner/ -run TestRowsToUpdates -v
```

Expected: all six tests PASS.

- [ ] **Step 5: Verify cross-platform build**

```bash
go build ./...
```

Expected: clean on Linux (Windows file dormant).

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/arp_seed_windows.go internal/scanner/arp_seed_windows_test.go
git commit -m "scanner: add Windows ARP seed scaffold with pure rowsToUpdates

The data-shaping helper is fully unit-tested with fabricated rows. The
SeedFromKernelARP entry point is stubbed; iphlpapi.GetIpNetTable2 wiring
lands in the next commit."
```

---

## Task 8: Wire `SeedFromKernelARP` to `iphlpapi.GetIpNetTable2`

**Files:**
- Modify: `internal/scanner/arp_seed_windows.go`

Replace the stub with a real syscall-driven implementation. No new unit tests; covered by the manual smoke test.

- [ ] **Step 1: Replace the stub `SeedFromKernelARP` and add syscall plumbing**

In `internal/scanner/arp_seed_windows.go`, add these imports to the existing import block:

```go
	"unsafe"

	"golang.org/x/sys/windows"
```

Then replace the `SeedFromKernelARP` stub at the bottom of the file with:

```go
// MIB_IPNET_ROW2 layout per Win32 (sufficient subset; only the fields we
// consume are mapped, but the size MUST match the C struct exactly).
// Layout source: <netioapi.h>. Total size = 88 bytes on x64.
type mibIpnetRow2 struct {
	Address              sockaddrInet
	InterfaceIndex       uint32
	InterfaceLuid        uint64
	PhysicalAddress      [32]byte
	PhysicalAddressLength uint32
	State                uint32 // NL_NEIGHBOR_STATE
	Flags                uint8
	ReachabilityTime     uint32
}

// sockaddrInet matches Win32 SOCKADDR_INET union (28 bytes — sized to the
// IPv6 member). We only read the IPv4 view.
type sockaddrInet struct {
	Family uint16
	Port   uint16
	Addr4  [4]byte
	_      [20]byte // padding to SOCKADDR_INET6 size
}

const (
	nlNeighborStateUnreachable = 0
	nlNeighborStateIncomplete  = 1
	nlNeighborStateProbe       = 2
	nlNeighborStateDelay       = 3
	nlNeighborStateStale       = 4
	nlNeighborStateReachable   = 5
)

func neighborReachable(state uint32) bool {
	switch state {
	case nlNeighborStateReachable,
		nlNeighborStateStale,
		nlNeighborStateDelay,
		nlNeighborStateProbe:
		return true
	}
	return false
}

var (
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable2    = iphlpapi.NewProc("GetIpNetTable2")
	procFreeMibTable      = iphlpapi.NewProc("FreeMibTable")
)

// mibIpnetTable2Header matches the start of MIB_IPNET_TABLE2 — a 32-bit
// NumEntries followed by the row array. We read NumEntries, then index
// into the array via pointer arithmetic.
type mibIpnetTable2Header struct {
	NumEntries uint32
	_          [4]byte // padding for 8-byte alignment of the row array
}

// SeedFromKernelARP reads the IPv4 neighbor table via iphlpapi and emits
// one Update per reachable entry on the chosen interface within subnet.
// Best-effort: returns nil on any failure.
func SeedFromKernelARP(ifaceName string, subnet *net.IPNet) []Update {
	if ifaceName == "" || subnet == nil {
		return nil
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}

	const AF_INET = 2
	var tablePtr uintptr
	ret, _, _ := procGetIpNetTable2.Call(uintptr(AF_INET), uintptr(unsafe.Pointer(&tablePtr)))
	if ret != 0 || tablePtr == 0 {
		return nil
	}
	defer procFreeMibTable.Call(tablePtr)

	header := (*mibIpnetTable2Header)(unsafe.Pointer(tablePtr))
	num := int(header.NumEntries)
	if num == 0 {
		return nil
	}
	rowsBase := unsafe.Pointer(uintptr(tablePtr) + unsafe.Sizeof(*header))
	rowSize := unsafe.Sizeof(mibIpnetRow2{})

	rows := make([]arpRow, 0, num)
	for i := 0; i < num; i++ {
		raw := (*mibIpnetRow2)(unsafe.Pointer(uintptr(rowsBase) + uintptr(i)*rowSize))
		if raw.Address.Family != AF_INET {
			continue
		}
		ip := net.IPv4(raw.Address.Addr4[0], raw.Address.Addr4[1], raw.Address.Addr4[2], raw.Address.Addr4[3])
		mac := make(net.HardwareAddr, 0, 6)
		if raw.PhysicalAddressLength == 6 {
			mac = append(mac, raw.PhysicalAddress[0:6]...)
		}
		rows = append(rows, arpRow{
			IfaceIndex: raw.InterfaceIndex,
			IP:         ip,
			MAC:        mac,
			Reachable:  neighborReachable(raw.State),
		})
	}
	return rowsToUpdates(rows, uint32(iface.Index), subnet, time.Now())
}
```

- [ ] **Step 2: Build on Windows**

On Windows:

```powershell
go build ./internal/scanner/
```

Expected: clean build.

- [ ] **Step 3: Run unit tests**

On Windows:

```powershell
go test ./internal/scanner/ -v
```

Expected: existing tests pass; `rowsToUpdates` tests still pass; the `SeedFromKernelARP` path itself isn't unit-tested.

- [ ] **Step 4: Quick on-host sanity check (optional but encouraged)**

In a small scratch file or `go run` snippet on the Windows host, call `SeedFromKernelARP` with your real adapter name and home subnet, and confirm the returned slice contains at least your gateway. (Don't commit the scratch.)

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/arp_seed_windows.go
git commit -m "scanner: seed ARP cache via iphlpapi.GetIpNetTable2 on Windows

SeedFromKernelARP reads the IPv4 neighbor table and emits one arp-seed
Update per reachable entry on the chosen interface within subnet. Matches
the Linux contract: best-effort, returns nil on any error."
```

---

## Task 9: Platform-aware precheck-failure hint in `main.go`

**Files:**
- Modify: `cmd/lan-inventory/main.go`

Replace the hardcoded `setcap` message with a `runtime.GOOS` switch.

- [ ] **Step 1: Edit `main.go`**

Add `"runtime"` to the existing import block.

Replace these three lines:

```go
		fmt.Fprintln(os.Stderr, "lan-inventory: needs raw socket access to sniff ARP and send ICMP.")
		fmt.Fprintln(os.Stderr, "Either run with sudo, or grant capabilities once:")
		fmt.Fprintln(os.Stderr, "    sudo setcap cap_net_raw,cap_net_admin=eip $(which lan-inventory)")
```

with:

```go
		fmt.Fprintln(os.Stderr, "lan-inventory: needs packet-capture access on this interface.")
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

- [ ] **Step 2: Build and run a sanity check**

```bash
go build ./cmd/lan-inventory
```

Expected: clean. The precheck path is hard to trigger without removing privileges; visual inspection of the diff is enough here.

- [ ] **Step 3: Commit**

```bash
git add cmd/lan-inventory/main.go
git commit -m "cli: print platform-specific privilege hint on precheck failure

Linux hint is unchanged (sudo / setcap). Windows hint points the user at
the Npcap installer. Other platforms get a generic message."
```

---

## Task 10: Update `README.md` — Windows install + drop "Linux only"

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Edit the Install section**

Replace the current Install section (lines 19–35 of the README) with:

````markdown
## Install

### Linux

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

The `setcap` step is needed once; `lan-inventory` needs raw-socket access
to sniff ARP packets and send ICMP ping. Without it the tool refuses to
start.

### Windows

1. Install [Npcap](https://npcap.com/) and check
   **"WinPcap API-compatible mode"** during install. The driver grants
   user-level packet capture so the binary runs from an ordinary
   (non-elevated) terminal.
2. Install the binary:

   ```powershell
   go install github.com/lab1702/lan-inventory/cmd/lan-inventory@latest
   lan-inventory
   ```

ICMP echo uses the unprivileged `IcmpSendEcho` Win32 API on Windows, so
no Administrator prompt is needed at runtime.
````

- [ ] **Step 2: Update the Limitations section**

Replace this bullet:

```markdown
- Linux only. Default-route detection and the kernel-ARP-cache seed are
  Linux-specific; macOS and Windows builds will fail at startup until those
  are implemented.
```

with:

```markdown
- Supported on Linux and Windows. macOS and *BSD builds compile but fail
  at startup (default-route detection is not implemented for those
  platforms).
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add Windows install instructions; drop Linux-only claim"
```

---

## Task 11: Makefile comment for Windows users

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add a comment near the `build` target**

Before the `build:` line, insert:

```makefile
# Windows users: run `go build ./cmd/lan-inventory` directly — the setcap
# step does not apply. Npcap install handles capture privilege at install
# time.
```

- [ ] **Step 2: Commit**

```bash
git add Makefile
git commit -m "build: note Windows workflow in Makefile

The Makefile is Linux-centric (sudo, setcap, curl). Windows users use the
go toolchain directly; comment makes that explicit so contributors don't
try to port the Makefile."
```

---

## Task 12: CI matrix — add `windows-latest` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Replace the workflow file**

Replace the entire contents of `.github/workflows/ci.yml` with:

```yaml
name: CI

on:
  push:
    branches: [master, main, 'feat/**']
  pull_request:

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Install libpcap (Linux)
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y libpcap-dev

      - name: Install Npcap SDK (Windows)
        if: runner.os == 'Windows'
        shell: pwsh
        run: |
          $sdk = "$env:RUNNER_TEMP\npcap-sdk"
          New-Item -ItemType Directory -Force $sdk | Out-Null
          Invoke-WebRequest https://npcap.com/dist/npcap-sdk-1.13.zip -OutFile "$env:RUNNER_TEMP\sdk.zip"
          Expand-Archive "$env:RUNNER_TEMP\sdk.zip" -DestinationPath $sdk -Force
          echo "CGO_CFLAGS=-I$sdk\Include" >> $env:GITHUB_ENV
          echo "CGO_LDFLAGS=-L$sdk\Lib\x64" >> $env:GITHUB_ENV

      - run: go vet ./...
      - run: go run honnef.co/go/tools/cmd/staticcheck@latest ./...
      - run: go test ./...
```

- [ ] **Step 2: Validate YAML locally (optional)**

If `yamllint` is installed:

```bash
yamllint .github/workflows/ci.yml
```

Otherwise, visually inspect indentation and `if:` conditions.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add windows-latest matrix job with Npcap SDK install

CI now runs vet, staticcheck, and go test on Ubuntu (existing) and Windows
(new). The Windows runner downloads the pinned Npcap SDK 1.13 zip and sets
CGO_CFLAGS / CGO_LDFLAGS so gopacket/pcap builds against it."
```

- [ ] **Step 4: Push the branch and watch the Windows job**

```bash
git push origin HEAD
```

Open the resulting Actions run and confirm both `ubuntu-latest` and
`windows-latest` jobs go green. If Windows fails:
- `gopacket/pcap` link errors → adjust `CGO_LDFLAGS` path (try `Lib\` without `x64` if the runner is 32-bit, but `windows-latest` is x64 today).
- Npcap SDK URL 404 → bump the pinned version in the CI step and the spec doc.

---

## Task 13: Manual smoke test on a real Windows host

This is a verification step, not a code change. Run on your Windows 11 machine before declaring the work done.

- [ ] **Step 1: Confirm Npcap is installed in WinPcap-API-compatible mode**

Open **Control Panel → Programs and Features** and verify "Npcap" is
present. If it was installed without the WinPcap compatibility checkbox,
re-run the installer with that option checked.

- [ ] **Step 2: Build the binary**

```powershell
go build -o lan-inventory.exe .\cmd\lan-inventory
```

Expected: clean build (cgo links against Npcap SDK).

- [ ] **Step 3: `--version` smoke**

```powershell
.\lan-inventory.exe --version
```

Expected: prints `lan-inventory 0.1.0` and exits 0.

- [ ] **Step 4: `--once --table` smoke (from a non-elevated PowerShell)**

```powershell
.\lan-inventory.exe --once --table
```

Expected: prints a table with multiple devices; each row has IP, MAC,
vendor, hostname; exit code 0. Confirm at least one Windows host on the
LAN appears with MAC + vendor (proves the ARP seed is working).

- [ ] **Step 5: TUI smoke**

```powershell
.\lan-inventory.exe
```

Expected: TUI opens, four tabs render, `/` filter works, `↑/↓` navigates,
`r` triggers a rescan, `q` quits cleanly.

- [ ] **Step 6: Permission negative test (delete this step after confirming)**

Temporarily disable the Npcap service (`net stop npcap` from an elevated
prompt), then run `.\lan-inventory.exe --version` from a normal prompt.
Expected: still exits 0 (version doesn't open pcap). Then run
`.\lan-inventory.exe --once --table`. Expected: exit code 2 and the new
Windows-specific hint message. Re-enable the service (`net start npcap`)
when done.

- [ ] **Step 7: Document the smoke result**

Add a one-line note to the PR body or commit message confirming the smoke
test passed on Windows 11 with Npcap <installed version>. No code change.

---

## Notes for the implementer

- The Linux build path is unchanged at every step. After every commit, run `go build ./...` on Linux (or in CI) to confirm.
- Tests tagged `//go:build windows` will not be run on the Linux CI runner — that's intentional. The Windows CI runner picks them up.
- If `pro-bing` ever changes how it reports TTL in unprivileged mode, the OS-detection rules in `probe/osguess.go` will still receive a TTL value; only the bucket choice may shift by a hop or two. The smoke test covers this.
- The `MIB_IPNET_ROW2` struct layout in Task 8 is sized for x64. If you later need 32-bit Windows support, audit the padding.
